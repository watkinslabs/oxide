//! The signature a descriptor may carry, and what it takes to accept it.
//!
//! The hash tree makes a file's bytes self-consistent: every block agrees
//! with the root the descriptor names. It says nothing about who chose that
//! root. Anything that can write the file's tail can write a new tree and a
//! new descriptor, and every read of the tampered file then verifies
//! perfectly. A built-in signature is what ties the root to a key, and
//! reading one without checking it — the state this file replaces — is
//! strictly worse than carrying none: it looks like authentication and is
//! not.
//!
//! What is signed is the DESCRIPTOR's digest, not the root hash. The salt,
//! the block size and the length the tree was built over all live in the
//! descriptor, and none of them is recoverable from the root — so signing the
//! root alone would leave an attacker free to re-describe the same tree as
//! another file's.
//!
//! Two rules from the reference that are easy to get backwards:
//!
//! - **A signature present is always checked**, whatever the policy says. The
//!   policy decides whether an ABSENT signature is tolerated, never whether a
//!   present one is examined.
//! - **An empty keyring rejects a signed file** rather than accepting it for
//!   want of anything to check against, and does so without parsing the
//!   signature at all — an unparsed blob is one less thing reachable by
//!   anyone who can turn verity on.

use alloc::vec::Vec;

use pkey::pkcs7::{self, Pkcs7Error, TrustStore};

use super::uapi::U16_LEN;
use super::VerityError;

/// Prefix the signed blob carries, so a key used for other purposes cannot
/// have one of its signatures replayed as a file measurement.
pub const MAGIC: &[u8] = b"FSVerity";
/// Offsets within the signed blob.
pub const F_MAGIC: usize = 0;
pub const F_ALGORITHM: usize = F_MAGIC + 8;
pub const F_SIZE: usize = F_ALGORITHM + U16_LEN;
pub const F_DIGEST: usize = F_SIZE + U16_LEN;

/// What this mount will accept.
///
/// The store is the set of certificates a signature's chain must reach — the
/// reference keeps exactly one such keyring for the whole system, and an
/// empty one means built-in signatures are compiled in but unused.
#[derive(Default)]
pub struct Policy {
    pub store: TrustStore,
    /// Whether an unsigned verity file may be read at all.
    pub require: bool,
}

impl Policy {
    /// A policy that trusts nothing and demands nothing: an unsigned file
    /// reads, and a signed one is refused because there is no key to check
    /// it against. # C: O(1)
    pub fn new() -> Self { Self { store: TrustStore::new(), require: false } }

    /// Trust a DER certificate. # C: O(len)
    pub fn trust(&mut self, der: &[u8]) -> Result<(), VerityError> {
        self.store.add(der).map_err(|_| VerityError::MalformedSignature)
    }
}

/// The bytes a signature is over: the magic, the algorithm, the digest width
/// and the digest itself.
///
/// The width is part of what is signed, so a signature over a SHA-256
/// measurement cannot be re-presented as the first 32 bytes of a SHA-512 one.
/// # C: O(digest)
pub fn formatted(alg: u8, digest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(F_DIGEST + digest.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&u16::from(alg).to_le_bytes());
    out.extend_from_slice(&(digest.len() as u16).to_le_bytes());
    out.extend_from_slice(digest);
    out
}

/// Check a descriptor's built-in signature against the policy.
///
/// `sig` is the signature appended to the descriptor, empty when there is
/// none. `file_digest` is the descriptor's own digest, which is what a signer
/// signs.
/// # C: O(chain * rsa)
pub fn verify(policy: &Policy, alg: u8, file_digest: &[u8], sig: &[u8])
    -> Result<(), VerityError> {
    if sig.is_empty() {
        // Only the absence is a policy question.
        if policy.require { return Err(VerityError::SignatureRequired); }
        return Ok(());
    }
    if policy.store.is_empty() { return Err(VerityError::NoKey); }
    let signed = formatted(alg, file_digest);
    pkcs7::detached(&signed, sig, &policy.store).map_err(errno_of)
}

/// Why a signature was not accepted, kept apart because a caller acts
/// differently on each: a malformed blob is a broken file, a rejected key is
/// tampering, and a missing key is a configuration. # C: O(1)
fn errno_of(e: Pkcs7Error) -> VerityError {
    match e {
        Pkcs7Error::BadMessage => VerityError::MalformedSignature,
        Pkcs7Error::KeyRejected => VerityError::BadSignature,
        Pkcs7Error::NoKey => VerityError::NoKey,
        Pkcs7Error::NoPackage => VerityError::UnsupportedHash,
    }
}

#[cfg(test)]
#[path = "../tests/veritysig.rs"]
mod tests;
