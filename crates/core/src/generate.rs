//! Secret generation from the OS CSPRNG with unbiased sampling.

use crate::crypto::{fill_random, CryptoError};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// Conservative default symbol set: safe in shells, YAML, URLs and most
/// password forms without quoting surprises.
const SYMBOLS: &str = "!@#%^*-_=+";
const AMBIGUOUS: &str = "Il1O0o";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Policy {
    /// Character-class password.
    Password {
        #[serde(default = "d_len")]
        length: usize,
        #[serde(default = "d_true")]
        lower: bool,
        #[serde(default = "d_true")]
        upper: bool,
        #[serde(default = "d_true")]
        digits: bool,
        /// `None` = default symbol set, `Some("")` = no symbols.
        #[serde(default)]
        symbols: Option<String>,
        #[serde(default)]
        exclude_ambiguous: bool,
    },
    /// Random bytes, hex encoded (`bytes` of entropy).
    Hex {
        #[serde(default = "d_bytes")]
        bytes: usize,
    },
    /// Random bytes, base64url (no padding).
    Base64url {
        #[serde(default = "d_bytes")]
        bytes: usize,
    },
}

fn d_len() -> usize {
    32
}
fn d_true() -> bool {
    true
}
fn d_bytes() -> usize {
    32
}

impl Default for Policy {
    fn default() -> Self {
        Policy::Password {
            length: 32,
            lower: true,
            upper: true,
            digits: true,
            symbols: None,
            exclude_ambiguous: false,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GenError {
    #[error("invalid generation policy: {0}")]
    Policy(&'static str),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Uniform integer in `0..n` by rejection sampling (no modulo bias).
fn uniform(n: u32) -> Result<u32, CryptoError> {
    debug_assert!(n > 0);
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let mut b = [0u8; 4];
        fill_random(&mut b)?;
        let v = u32::from_le_bytes(b);
        if v < zone {
            return Ok(v % n);
        }
    }
}

pub fn generate(policy: &Policy) -> Result<Zeroizing<String>, GenError> {
    match policy {
        Policy::Hex { bytes } => {
            check_bytes(*bytes)?;
            let raw = Zeroizing::new(crate::crypto::random_bytes(*bytes)?);
            let mut s = Zeroizing::new(String::with_capacity(bytes * 2));
            for b in raw.iter() {
                s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
                s.push(char::from_digit((b & 15) as u32, 16).unwrap());
            }
            Ok(s)
        }
        Policy::Base64url { bytes } => {
            check_bytes(*bytes)?;
            let raw = Zeroizing::new(crate::crypto::random_bytes(*bytes)?);
            Ok(Zeroizing::new(b64url(&raw)))
        }
        Policy::Password { length, lower, upper, digits, symbols, exclude_ambiguous } => {
            if *length < 12 || *length > 256 {
                return Err(GenError::Policy("length must be 12..=256"));
            }
            let sym = symbols.as_deref().unwrap_or(SYMBOLS);
            if sym.len() > 64 || !sym.chars().all(|c| c.is_ascii_punctuation()) {
                return Err(GenError::Policy("symbols must be ASCII punctuation, max 64"));
            }
            let mut classes: Vec<Vec<char>> = Vec::new();
            for (on, set) in [(*lower, LOWER), (*upper, UPPER), (*digits, DIGITS), (true, sym)] {
                if !on {
                    continue;
                }
                let mut chars: Vec<char> = set
                    .chars()
                    .filter(|c| !(*exclude_ambiguous && AMBIGUOUS.contains(*c)))
                    .collect();
                chars.sort_unstable();
                chars.dedup();
                if !chars.is_empty() {
                    classes.push(chars);
                }
            }
            let all: Vec<char> = classes.iter().flatten().copied().collect();
            if all.len() < 10 {
                return Err(GenError::Policy("character set too small"));
            }
            // One guaranteed character from every enabled class, the rest from
            // the full set, then a Fisher-Yates shuffle so positions are uniform.
            let mut out: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(*length));
            for c in &classes {
                out.push(c[uniform(c.len() as u32)? as usize]);
            }
            while out.len() < *length {
                out.push(all[uniform(all.len() as u32)? as usize]);
            }
            for i in (1..out.len()).rev() {
                let j = uniform(i as u32 + 1)? as usize;
                out.swap(i, j);
            }
            Ok(Zeroizing::new(out.iter().collect()))
        }
    }
}

fn check_bytes(n: usize) -> Result<(), GenError> {
    if !(16..=512).contains(&n) {
        return Err(GenError::Policy("bytes must be 16..=512"));
    }
    Ok(())
}

fn b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::with_capacity(data.len() * 4 / 3 + 3);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            s.push(T[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            s.push(T[n as usize & 63] as char);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_password_has_all_classes() {
        for _ in 0..200 {
            let p = generate(&Policy::default()).unwrap();
            assert_eq!(p.chars().count(), 32);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn no_symbols_and_no_ambiguous() {
        let pol = Policy::Password {
            length: 40,
            lower: true,
            upper: true,
            digits: true,
            symbols: Some(String::new()),
            exclude_ambiguous: true,
        };
        for _ in 0..100 {
            let p = generate(&pol).unwrap();
            assert!(p.chars().all(|c| c.is_ascii_alphanumeric() && !AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn rejects_weak_policies() {
        let short = Policy::Password {
            length: 6,
            lower: true,
            upper: true,
            digits: true,
            symbols: None,
            exclude_ambiguous: false,
        };
        assert!(generate(&short).is_err());
        let tiny = Policy::Password {
            length: 20,
            lower: false,
            upper: false,
            digits: false,
            symbols: Some("!".into()),
            exclude_ambiguous: false,
        };
        assert!(generate(&tiny).is_err());
        assert!(generate(&Policy::Hex { bytes: 4 }).is_err());
    }

    #[test]
    fn outputs_differ_and_encode_correctly() {
        let a = generate(&Policy::Hex { bytes: 32 }).unwrap();
        let b = generate(&Policy::Hex { bytes: 32 }).unwrap();
        assert_eq!(a.len(), 64);
        assert_ne!(*a, *b);
        assert_eq!(b64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(generate(&Policy::Base64url { bytes: 32 }).unwrap().len(), 43);
    }

    #[test]
    fn uniform_is_roughly_flat() {
        let mut counts = [0u32; 7];
        for _ in 0..70_000 {
            counts[uniform(7).unwrap() as usize] += 1;
        }
        for c in counts {
            assert!((9_000..11_000).contains(&c), "bucket {c} far from 10000");
        }
    }
}
