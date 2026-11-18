//! Rotation drivers: how the vault pushes a new secret to the system that uses it.
//!
//! The secret only ever travels on the child process's stdin. It is never put
//! in argv, the environment, a temp file or a log line. Driver configuration
//! is admin-only, because it decides what commands run.

use serde::{Deserialize, Serialize};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Driver {
    /// Run a command on a remote host over SSH (key auth, known host keys only).
    Ssh {
        host: String,
        #[serde(default = "d_port")]
        port: u16,
        user: String,
        /// Remote command, e.g. `chpasswd`.
        command: String,
        /// Text written to the command's stdin. Placeholders: `{{new}}`,
        /// `{{old}}`, `{{username}}`. Example for chpasswd: `{{username}}:{{new}}\n`.
        stdin: String,
        #[serde(default = "d_timeout")]
        timeout_secs: u64,
    },
    /// Run a local program on the vault host (for API-based rotations).
    Exec {
        /// Absolute program path followed by its arguments. No shell.
        argv: Vec<String>,
        stdin: String,
        #[serde(default = "d_timeout")]
        timeout_secs: u64,
    },
}

fn d_port() -> u16 {
    22
}
fn d_timeout() -> u64 {
    30
}

fn hostish(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

impl Driver {
    pub fn validate(&self) -> Result<(), String> {
        let (stdin, timeout) = match self {
            Driver::Ssh { host, port, user, command, stdin, timeout_secs } => {
                // Strict allowlists: a host or user beginning with '-' would be
                // parsed by ssh as an option.
                if !hostish(host) {
                    return Err("invalid ssh host".into());
                }
                if !hostish(user) || user.len() > 32 {
                    return Err("invalid ssh user".into());
                }
                if *port == 0 {
                    return Err("invalid ssh port".into());
                }
                if command.trim().is_empty() || command.len() > 1024 || command.chars().any(|c| c.is_control()) {
                    return Err("invalid remote command".into());
                }
                if command.contains("{{") {
                    return Err("placeholders are only allowed in stdin, never in the command".into());
                }
                (stdin, timeout_secs)
            }
            Driver::Exec { argv, stdin, timeout_secs } => {
                if argv.is_empty() || argv.len() > 32 || !argv[0].starts_with('/') {
                    return Err("argv[0] must be an absolute path".into());
                }
                if argv.iter().any(|a| a.len() > 1024 || a.contains('\0') || a.contains("{{")) {
                    return Err("invalid argument (placeholders are only allowed in stdin)".into());
                }
                (stdin, timeout_secs)
            }
        };
        if stdin.len() > 4096 || !stdin.contains("{{new}}") {
            return Err("stdin template must contain {{new}} and be under 4 KiB".into());
        }
        if !(1..=300).contains(timeout) {
            return Err("timeout_secs must be 1..=300".into());
        }
        Ok(())
    }
}

/// Single-pass substitution, so a secret that happens to contain `{{old}}`
/// is never expanded again.
fn render(template: &str, new: &str, old: &str, username: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(template.len() + new.len() + old.len()));
    let mut rest = template;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let (val, skip) = if tail.starts_with("{{new}}") {
            (new, 7)
        } else if tail.starts_with("{{old}}") {
            (old, 7)
        } else if tail.starts_with("{{username}}") {
            (username, 12)
        } else {
            ("{{", 2)
        };
        out.push_str(val);
        rest = &tail[skip..];
    }
    out.push_str(rest);
    out
}

/// Remove any echo of the secret from driver output before it is logged.
fn scrub(text: &str, secrets: &[&str]) -> String {
    let mut t = text.to_string();
    for s in secrets {
        if s.len() >= 4 {
            t = t.replace(s, "[redacted]");
        }
    }
    t.chars().filter(|c| !c.is_control() || *c == ' ').take(300).collect()
}

pub async fn run(driver: &Driver, new: &str, old: &str, username: &str) -> Result<(), String> {
    driver.validate()?;
    let (mut cmd, template, timeout) = match driver {
        Driver::Ssh { host, port, user, command, stdin, timeout_secs } => {
            let mut c = Command::new("ssh");
            c.args([
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=10",
                "-o", "ForwardAgent=no",
                "-o", "ClearAllForwardings=yes",
                "-T",
                "-p", &port.to_string(),
                "-l", user,
                "--", host, command,
            ]);
            (c, stdin, *timeout_secs)
        }
        Driver::Exec { argv, stdin, timeout_secs } => {
            let mut c = Command::new(&argv[0]);
            c.args(&argv[1..]);
            c.env_clear().env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
            (c, stdin, *timeout_secs)
        }
    };
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let mut child = cmd.spawn().map_err(|e| format!("driver failed to start: {e}"))?;
    let input = render(template, new, old, username);
    let mut stdin = child.stdin.take().ok_or("driver stdin unavailable")?;
    let work = async {
        // Ignore EPIPE here: the exit status decides success.
        let _ = stdin.write_all(input.as_bytes()).await;
        let _ = stdin.shutdown().await;
        drop(stdin);
        child.wait_with_output().await
    };
    let out = match tokio::time::timeout(Duration::from_secs(timeout), work).await {
        Err(_) => return Err(format!("driver timed out after {timeout}s")),
        Ok(Err(e)) => return Err(format!("driver I/O error: {e}")),
        Ok(Ok(o)) => o,
    };
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!(
            "driver exited with {}: {}",
            out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
            scrub(&err, &[new, old])
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec(argv: &[&str], stdin: &str) -> Driver {
        Driver::Exec { argv: argv.iter().map(|s| s.to_string()).collect(), stdin: stdin.into(), timeout_secs: 5 }
    }

    #[test]
    fn render_is_single_pass() {
        assert_eq!(render("{{username}}:{{new}}\n", "N", "O", "root").as_str(), "root:N\n");
        // A new value containing a placeholder must not pull in the old secret.
        assert_eq!(render("{{new}}", "x{{old}}y", "OLD", "u").as_str(), "x{{old}}y");
        assert_eq!(render("a{{b}}c{{", "N", "O", "u").as_str(), "a{{b}}c{{");
    }

    #[test]
    fn validation_blocks_injection() {
        let ssh = |host: &str, user: &str, command: &str| Driver::Ssh {
            host: host.into(),
            port: 22,
            user: user.into(),
            command: command.into(),
            stdin: "{{new}}".into(),
            timeout_secs: 10,
        };
        assert!(ssh("hypervisor-1", "root", "chpasswd").validate().is_ok());
        assert!(ssh("-oProxyCommand=evil", "root", "chpasswd").validate().is_err());
        assert!(ssh("host", "-oProxyCommand=evil", "chpasswd").validate().is_err());
        assert!(ssh("host;rm", "root", "chpasswd").validate().is_err());
        assert!(ssh("host", "root", "echo {{new}}").validate().is_err());
        assert!(exec(&["true"], "{{new}}").validate().is_err());
        assert!(exec(&["/bin/echo", "{{new}}"], "{{new}}").validate().is_err());
        assert!(exec(&["/usr/bin/true"], "no placeholder").validate().is_err());
    }

    #[test]
    fn scrub_redacts() {
        assert_eq!(scrub("bad password: hunter22!", &["hunter22!"]), "bad password: [redacted]");
    }

    #[tokio::test]
    async fn exec_driver_gets_secret_on_stdin_only() {
        let dir = std::env::temp_dir().join(format!("jaword-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out");
        let d = exec(&["/usr/bin/tee", out.to_str().unwrap()], "{{username}}:{{new}}");
        run(&d, "NEWSECRET", "OLD", "svc").await.unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "svc:NEWSECRET");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn exec_driver_failure_and_timeout() {
        let e = run(&exec(&["/usr/bin/false"], "{{new}}"), "n", "o", "u").await.unwrap_err();
        assert!(e.contains("exited with 1"), "{e}");
        let slow = Driver::Exec { argv: vec!["/bin/sleep".into(), "5".into()], stdin: "{{new}}".into(), timeout_secs: 1 };
        assert!(run(&slow, "n", "o", "u").await.unwrap_err().contains("timed out"));
    }
}
