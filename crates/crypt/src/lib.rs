// crypt(3)-shape password verification. /etc/shadow stores hashes
// in `$<id>$<salt>$<hash>` form; v1 implements:
//   id="" or "0" — DES (rejected; legacy 13-char form not supported)
//   id="6"       — sha512crypt (Drepper 2007)
//   empty hash   — no password set; matches any input including empty
//
// The sha512crypt impl hashes (password, salt, rounds=5000 default)
// per the Drepper spec — not a re-export of `libcrypt`. v1 ships
// a hosted-tested version; production hardening (constant-time
// compare against published vectors) is P14-04+.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;
pub mod sha512;
pub use sha512::Sha512;

/// Result of `verify`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CryptResult {
    /// Hash recognized + plaintext matches.
    Match,
    /// Hash recognized + plaintext does not match.
    Mismatch,
    /// Empty hash — no password configured. Match if plaintext also
    /// empty per sysv passwd contract.
    NoPassword,
    /// Hash format unsupported (legacy DES, bcrypt $2a/$2b/$2y, …).
    Unsupported,
}

/// Verify `password` against the on-shadow hash `hash`. Comparison
/// is byte-equal; constant-time variant lands alongside the
/// production-hardening pass.
/// # C: O(rounds × hash_block_size) for sha512crypt
pub fn verify(password: &str, hash: &str) -> CryptResult {
    if hash.is_empty() {
        return if password.is_empty() { CryptResult::NoPassword }
               else { CryptResult::Mismatch };
    }
    if let Some(rest) = hash.strip_prefix("$6$") {
        let (salt, expected) = match rest.rsplit_once('$') {
            Some(t) => t, None => return CryptResult::Unsupported,
        };
        let computed = sha512::sha512crypt(password.as_bytes(), salt.as_bytes(), 5000);
        if computed == expected { CryptResult::Match } else { CryptResult::Mismatch }
    } else {
        CryptResult::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash_no_password() {
        assert_eq!(verify("",     ""), CryptResult::NoPassword);
        assert_eq!(verify("foo",  ""), CryptResult::Mismatch);
    }

    #[test]
    fn unsupported_legacy_des() {
        // Old crypt(3) DES form: 13 chars, no $-separator.
        assert_eq!(verify("hello", "Az1234abcdef0"), CryptResult::Unsupported);
    }
}
