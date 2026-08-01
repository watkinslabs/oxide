// Asymmetric key material and the operations over it: DER decoding, the two
// blob formats a key arrives in (an X.509 certificate for a public key, a
// PKCS#8 blob for a private one), and RSA with its PKCS#1 v1.5 encodings.
//
// Module manifest:
// - der:    definite-length DER decoding. Owns every "is this well formed"
//           rule; no structure below re-implements one.
// - oid:    object identifiers, as encoded bytes, and the algorithm names
//           they map to.
// - rsa:    the RSA key and the raw primitive.
// - pkcs1:  EME/EMSA v1.5 encodings and the DigestInfo prefix table.
// - x509:   certificate parsing, including the name rendering the key
//           subsystem describes a certificate by.
// - pkcs8:  private-key blob parsing.
// - key:    `AsymmetricKey` — the parsed key a caller actually holds, its
//           supported-operation set, and the operation dispatch. This is the
//           one place an encoding name and an operation are turned into a
//           calculation.
//
// Nothing here reads a clock, a keyring or a random pool: entropy for
// encryption padding is passed IN, so every path is reproducible under test.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))] extern crate std;

pub mod der;
pub mod key;
pub mod oid;
pub mod pkcs1;
pub mod pkcs8;
pub mod rsa;
pub mod x509;

pub use key::{AsymmetricKey, KeyQuery, Operation};

/// Why an operation or a parse failed. The distinctions are the ones
/// userspace can act on, and each maps to exactly one errno at the syscall
/// boundary.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PkeyError {
    /// The blob does not decode, or a signature block is not the encoding it
    /// claims to be.
    BadMessage,
    /// Structurally fine, but not a key this kernel can use — a bad modulus
    /// size, a version it does not implement.
    BadKey,
    /// A well-formed request whose parameters cannot produce a result: an
    /// input at least as large as the modulus, a length that contradicts the
    /// encoding, an unusable combination of encoding and operation.
    Invalid,
    /// The output does not fit the width the operation produces.
    Overflow,
    /// The operation needs the private half and the key has only the public.
    NoPrivateKey,
    /// A signature verified as well formed but is not this key's signature
    /// over this digest.
    Rejected,
    /// The algorithm named is one this kernel has no implementation of.
    NoPackage,
    /// The named combination resolves to no registered algorithm — an unknown
    /// digest name, or an operation with no implementation for the encoding
    /// asked for.
    NoAlgorithm,
    /// The requested operation is not defined for this key and encoding.
    Unsupported,
}

#[cfg(test)] mod tests;
