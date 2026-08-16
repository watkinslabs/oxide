// Hash algorithm identity: the wire identifier, the digest length it implies,
// and the one place a digest is actually computed. Everything that needs a
// digest size asks here so no caller can pick a length by hand.

use alloc::vec::Vec;
use crypt::Digest;

use crate::uapi::{
    SHA1_DIGEST_SIZE, SHA256_DIGEST_SIZE, SHA384_DIGEST_SIZE, SHA512_DIGEST_SIZE,
    SM3_256_DIGEST_SIZE, TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512,
    TPM_ALG_SM3_256,
};

/// A hash algorithm a PCR bank can be allocated with.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Alg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sm3,
}

impl Alg {
    /// Wire identifier for this algorithm. # C: O(1)
    pub fn id(self) -> u16 {
        match self {
            Alg::Sha1 => TPM_ALG_SHA1,
            Alg::Sha256 => TPM_ALG_SHA256,
            Alg::Sha384 => TPM_ALG_SHA384,
            Alg::Sha512 => TPM_ALG_SHA512,
            Alg::Sm3 => TPM_ALG_SM3_256,
        }
    }

    /// Algorithm named by a wire identifier, or `None` when this build has no
    /// bank for it. Absence is reported, never substituted. # C: O(1)
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            TPM_ALG_SHA1 => Some(Alg::Sha1),
            TPM_ALG_SHA256 => Some(Alg::Sha256),
            TPM_ALG_SHA384 => Some(Alg::Sha384),
            TPM_ALG_SHA512 => Some(Alg::Sha512),
            TPM_ALG_SM3_256 => Some(Alg::Sm3),
            _ => None,
        }
    }

    /// Digest length in bytes. A PCR of this bank is exactly this wide.
    /// # C: O(1)
    pub fn digest_size(self) -> usize {
        match self {
            Alg::Sha1 => SHA1_DIGEST_SIZE,
            Alg::Sha256 => SHA256_DIGEST_SIZE,
            Alg::Sha384 => SHA384_DIGEST_SIZE,
            Alg::Sha512 => SHA512_DIGEST_SIZE,
            Alg::Sm3 => SM3_256_DIGEST_SIZE,
        }
    }

    /// Digest length for a wire identifier without constructing an `Alg`.
    /// # C: O(1)
    pub fn digest_size_of(id: u16) -> Option<usize> { Alg::from_id(id).map(|a| a.digest_size()) }

    /// The message-digest implementation backing this algorithm. `None` means
    /// this kernel cannot compute it, so a bank of that algorithm can be
    /// tracked on the wire but not extended locally. # C: O(1)
    pub fn digest_impl(self) -> Option<Digest> {
        match self {
            Alg::Sha1 => Some(Digest::Sha1),
            Alg::Sha256 => Some(Digest::Sha256),
            Alg::Sha384 => Some(Digest::Sha384),
            Alg::Sha512 => Some(Digest::Sha512),
            Alg::Sm3 => None,
        }
    }

    /// Hash the concatenation of `parts`. `None` when unsupported.
    /// # C: O(total input length)
    pub fn hash(self, parts: &[&[u8]]) -> Option<Vec<u8>> { self.digest_impl().map(|d| d.digest(parts)) }
}
