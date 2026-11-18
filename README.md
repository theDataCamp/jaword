# jaword

Self-hosted secrets vault built so AI agents can create, rotate and manage
credentials **without ever seeing them**. One Rust codebase: server with web
UI, CLI, and MCP server.

- Status: v0.1.0
- Intended deployment: a small container, loopback listener, HTTPS via a private overlay network (e.g. `tailscale serve`)

## How agents rotate a password they never see

1. Agent calls `secret_rotate("infra/pve/root")` over MCP (or `jaword rotate`).
2. The vault generates the new value and stores it as a `pending` version.
3. The vault's rotation driver pushes it to the real system (SSH command or
   local program). The secret travels on the child's stdin only.
4. Driver succeeds: pending becomes `current`. Driver fails: old value stays
   current, new one is parked as `failed`.
5. The agent gets back `{rotated: true, version: N}`. No value.

The MCP server has no tool that returns a value, and the server refuses
`reveal` for any token with role `agent`, whatever its rules say.

## Layout

| Path | What |
|---|---|
| `crates/core` | Crypto, generator, access rules. No I/O, so it can compile to WASM (browser extension) and mobile bindings later. |
| `crates/server` | `jawordd`: HTTP API, encrypted SQLite store, audit log, rotation drivers, embedded web UI. |
| `crates/cli` | `jaword`: CLI and `jaword mcp` (stdio MCP server). |
| `deploy/` | systemd unit and container provisioning script. |
| `tests/pentest.py` | Black-box attack suite (81 checks). |

## Security design

**Keys.** Passphrase → Argon2id (128 MiB, t=3) → wraps a random 256-bit master
key. A recovery key wraps the same master key. HKDF derives separate keys for
wrapping, metadata, audit, tokens and row integrity. The master key exists
only in server memory; after every restart the vault is **sealed** until
someone enters the passphrase.

**Storage.** Every secret version gets its own random data key
(XChaCha20-Poly1305), wrapped by the master-derived key. Usernames, URLs,
notes and driver configs are encrypted too. Each ciphertext is bound to its
row, and rows carry a MAC, so editing the database directly (swapping two
secrets, rolling a version back, upgrading a token to admin, un-revoking a
token) is detected rather than obeyed. API tokens are stored only as HMACs.

**Access.** Tokens have a role (`admin`, `human`, `agent`) and path rules like
`infra/**=list,generate,rotate`. Capabilities: `list create update generate
rotate delete write reveal`. `write` (supplying a value yourself) is separate
from `update` (metadata), so an agent cannot set a secret to something it
knows. Default deny.

**Audit.** Every action, including denied ones, goes to an HMAC-chained log.
`jaword audit --verify` detects edited or deleted rows.

**Network.** Listens on loopback only; Tailscale serve provides HTTPS. Host
and Origin pinning, strict CSP, bearer-token auth with no cookies, 64 KiB body
cap, header timeout, connection cap. `init` is refused through any proxy.

**Process.** No `unsafe` in this repo. systemd sandbox (no capabilities,
read-only filesystem, no core dumps), container has swap disabled.

### Known limits (read these)

- This protects secrets from the **model's context and transcripts**. An agent
  with a root shell on a target machine can still read a secret where it lands
  on that machine.
- A saved admin token on a workstation is readable by anything running as you.
  Do admin work in the web UI; keep only a scoped token on disk.
- Someone who can write the database **and** roll the whole file back to an
  older copy is not detected (no external anchor yet). Ship the audit log off
  the box to close that.
- Request bodies holding a secret are not wiped from server memory after use.
- Not independently audited. The pen test here was done by the same author as
  the code.

## Daily use

```bash
jaword ls infra/
jaword new infra/gitea/admin --username admin        # value generated in vault
jaword rotate infra/pve/root                         # push new value via driver
jaword show infra/pve/root                           # metadata + history
jaword reveal infra/pve/root                         # humans only
jaword run -e PGPASSWORD=infra/db/app -- psql ...    # inject into one command
jaword audit --verify
```

Every item has a **path** (its unique address, used by access rules and
agents, e.g. `infra/pve/root`) plus ordinary fields: name, website, username,
tags, notes.

### Import and export

```bash
jaword import export.csv --prefix logins --dry-run   # preview
jaword import export.csv --prefix logins --remove-source
jaword export --out backup.csv                       # humans only, plain text
jaword export --out inventory.csv --metadata-only    # no values, fine for agents
```

Import reads CSV exports from 1Password, Bitwarden, Chrome/Edge, Firefox,
LastPass and KeePassXC. One-time-code (TOTP) seeds are not imported yet.
Agents can run an import through the `secret_import_file` MCP tool: the tool
reads the file and returns only counts and paths. A full export is plain text
by nature, so it needs a token with `reveal`.

After a reboot of the container: open the web UI and enter the passphrase, or
run `jaword unseal`.

### Rotation drivers (admin only)

```json
{"type": "ssh", "host": "hypervisor-1", "user": "root",
 "command": "chpasswd", "stdin": "{{username}}:{{new}}\n"}
```

```bash
jaword driver infra/pve/root --file driver.json
```

`{{new}}`, `{{old}}`, `{{username}}` are allowed in `stdin` only, never in the
command line. The SSH driver uses key auth with strict host key checking, as
the `jaword` user inside the container (`/var/lib/jaword/.ssh`).

## Build, test, deploy

```bash
cargo test                                            # 40 unit tests
cargo build --release
cargo zigbuild --release --target x86_64-unknown-linux-musl   # static Linux
cargo audit                                           # dependency advisories
```

Pen test (throwaway instance only, it seals and tampers with the database):

```bash
python3 tests/pentest.py http://127.0.0.1:8212 init.json vault.db server.log
```

Server configuration is by environment: `JAWORD_DB`, `JAWORD_LISTEN`,
`JAWORD_ALLOWED_HOSTS` (see `deploy/jawordd.service`).

## Not built yet

Browser extension, mobile apps, passkey login, auto-unseal, built-in drivers
for specific APIs (Proxmox, Gitea, Cloudflare), Windows service packaging
(the CLI already builds for Windows; the server's signal handling is
Unix-only).

## License

Apache-2.0. See [LICENSE](LICENSE).
