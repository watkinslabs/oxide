// PKCS#7 / CMS SignedData: parsing a detached signature, checking it against
// the data it claims to sign, and deciding whether its certificate chain
// reaches a key already held.
//
// The three are deliberately separate answers. A blob can be a well-formed
// SignedData whose signature is wrong; a signature can be right over data
// nobody trusts the signer of. Collapsing them into one boolean is how a
// caller ends up unable to tell a corrupt file from a forged one.
//
// Module manifest:
// - `oids`:   the object identifiers the format is built from.
// - `parse`:  ContentInfo, SignedData and SignerInfo into their pieces.
// - `certid`: naming a certificate, and naming the one that signed it.
// - `chain`:  the certificate links the message asserts, each one checked.
// - `trust`:  the store of already-trusted certificates, and the walk into it.
// - `verify`: the digest the signature is over, and the whole decision.

pub mod oids;
pub mod parse;
pub mod certid;
pub mod chain;
pub mod trust;
pub mod verify;

pub use trust::TrustStore;
pub use verify::detached;

use crate::der::DerError;
use crate::PkeyError;

/// Why a signature was not accepted. The four are kept apart because a caller
/// acts differently on each: a malformed blob is a broken file, a rejected
/// key is an attack or a mismatch, a missing key is a configuration, and a
/// missing algorithm is a build that cannot answer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Pkcs7Error {
    /// Not a SignedData, or one whose structure contradicts itself.
    BadMessage,
    /// Well formed, and the signature does not verify under a key that should
    /// have produced it.
    KeyRejected,
    /// No certificate in the chain is one the store holds.
    NoKey,
    /// An algorithm this build has no implementation of.
    NoPackage,
}

impl From<DerError> for Pkcs7Error {
    /// Every decoding failure is one answer: the blob is not a signature.
    /// # C: O(1)
    fn from(_: DerError) -> Self { Pkcs7Error::BadMessage }
}

impl From<PkeyError> for Pkcs7Error {
    /// A key operation's failures map onto the same four answers. A signature
    /// that decodes but does not match is a REJECTED key, never a malformed
    /// message — a caller that conflated them could not tell a tampered file
    /// from a truncated one. # C: O(1)
    fn from(e: PkeyError) -> Self {
        match e {
            PkeyError::Rejected => Pkcs7Error::KeyRejected,
            PkeyError::NoPackage | PkeyError::NoAlgorithm | PkeyError::Unsupported =>
                Pkcs7Error::NoPackage,
            _ => Pkcs7Error::BadMessage,
        }
    }
}

#[cfg(test)]
#[path = "tests/pkcs7.rs"]
mod tests;
