// PKCS#8 `PrivateKeyInfo` — the form a private key is handed to the kernel in.
// It carries no name of its own, which is why a key added from one must be
// given a description by its caller.

use alloc::vec::Vec;

use crate::der::{self, Reader};
use crate::oid;
use crate::PkeyError;

/// `PrivateKeyInfo ::= SEQUENCE { version INTEGER, privateKeyAlgorithm
/// AlgorithmIdentifier, privateKey OCTET STRING, attributes [0] OPTIONAL }`.
/// Returns the algorithm name and the algorithm-specific private key.
/// # C: O(len)
pub fn parse(blob: &[u8]) -> Result<(&'static str, Vec<u8>), PkeyError> {
    let body = der::parse_exact(blob, der::TAG_SEQUENCE)?;
    let mut r = Reader::new(body);
    let version = der::positive_integer(r.expect(der::TAG_INTEGER)?)?;
    // Version 1 carries a public key alongside; nothing produces it for RSA.
    if version != [0] { return Err(PkeyError::BadKey); }
    let alg = r.expect(der::TAG_SEQUENCE)?;
    let mut ar = Reader::new(alg);
    let algo = oid::pkey_algo(ar.expect(der::TAG_OID)?).ok_or(PkeyError::NoPackage)?;
    let key = r.expect(der::TAG_OCTET_STRING)?.to_vec();
    Ok((algo, key))
}
