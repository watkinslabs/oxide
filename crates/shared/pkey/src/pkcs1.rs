// PKCS#1 v1.5 encodings (RFC 8017): EME for encryption and EMSA for
// signatures, plus the DigestInfo prefix table the signature encoding
// prepends.
//
// The kernel never hashes anything here — a signature operation takes the
// digest from userspace and the prefix names which algorithm produced it — so
// the table is pure bytes and covers every prefix a caller can name.

use alloc::vec::Vec;

use crate::rsa::RsaKey;
use crate::PkeyError;

/// Smallest padding string the encodings allow; a block with fewer than eight
/// padding octets is refused in both directions.
pub const MIN_PS: usize = 8;
/// Fixed overhead of a v1.5 block: leading zero, block type, the padding
/// terminator, and the minimum padding.
pub const V15_OVERHEAD: usize = 3 + MIN_PS;

/// A DigestInfo prefix: the ASN.1 header naming a digest algorithm, whose
/// final octet is the digest length that algorithm produces.
pub struct HashPrefix {
    pub name: &'static str,
    pub data: &'static [u8],
}

/// Every prefix a signature may be encoded with. `none` is the empty prefix
/// used by protocols that sign a bare hash, and it is the default when a
/// caller names no digest.
pub static HASH_PREFIXES: &[HashPrefix] = &[
    HashPrefix { name: "none", data: &[] },
    HashPrefix { name: "md5", data: &[
        0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
        0x05, 0x00, 0x04, 0x10] },
    HashPrefix { name: "sha1", data: &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14] },
    HashPrefix { name: "rmd160", data: &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14] },
    HashPrefix { name: "sha256", data: &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20] },
    HashPrefix { name: "sha384", data: &[
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30] },
    HashPrefix { name: "sha512", data: &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40] },
    HashPrefix { name: "sha224", data: &[
        0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
        0x05, 0x00, 0x04, 0x1c] },
    HashPrefix { name: "sha3-256", data: &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
        0x05, 0x00, 0x04, 0x20] },
    HashPrefix { name: "sha3-384", data: &[
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
        0x05, 0x00, 0x04, 0x30] },
    HashPrefix { name: "sha3-512", data: &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a,
        0x05, 0x00, 0x04, 0x40] },
];

/// Resolve a digest name to its prefix. # C: O(prefixes)
pub fn hash_prefix(name: &str) -> Option<&'static HashPrefix> {
    HASH_PREFIXES.iter().find(|p| p.name == name)
}

impl HashPrefix {
    /// Is `len` the digest length this prefix declares? The empty prefix
    /// declares nothing, so any length passes it. # C: O(1)
    pub fn accepts_digest_len(&self, len: usize) -> bool {
        match self.data.last() { None => true, Some(&declared) => len == declared as usize }
    }
}

/// EME-PKCS1-v1_5 encryption. The padding string is nonzero random octets, so
/// the same message encrypts differently every time — that randomness is the
/// scheme's security, not a detail. # C: O(k + rsa)
pub fn encrypt<R: FnMut(&mut [u8])>(key: &RsaKey, msg: &[u8], mut rand: R)
    -> Result<Vec<u8>, PkeyError>
{
    let k = key.size();
    if msg.len() + V15_OVERHEAD > k { return Err(PkeyError::Overflow); }
    let ps_len = k - msg.len() - 3;
    let mut em: Vec<u8> = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x02);
    let mut ps = alloc::vec![0u8; ps_len];
    rand(&mut ps);
    // A zero octet would terminate the padding early, so each one is redrawn
    // rather than mapped onto a fixed value, which would bias the padding.
    for b in ps.iter_mut() {
        while *b == 0 {
            let mut one = [0u8; 1];
            rand(&mut one);
            *b = one[0];
        }
    }
    em.extend_from_slice(&ps);
    em.push(0x00);
    em.extend_from_slice(msg);
    key.public_op(&em)
}

/// EME-PKCS1-v1_5 decryption, returning the message. Every malformed block
/// reports the same error whatever is wrong with it. # C: O(k + rsa)
pub fn decrypt(key: &RsaKey, ct: &[u8]) -> Result<Vec<u8>, PkeyError> {
    let k = key.size();
    if ct.len() != k { return Err(PkeyError::Invalid); }
    let em = key.private_op(ct)?;
    if em[0] != 0x00 || em[1] != 0x02 { return Err(PkeyError::Invalid); }
    let sep = em[2..].iter().position(|&b| b == 0).ok_or(PkeyError::Invalid)?;
    if sep < MIN_PS { return Err(PkeyError::Invalid); }
    Ok(em[3 + sep..].to_vec())
}

/// EMSA-PKCS1-v1_5 signature generation over an already-computed digest.
/// # C: O(k + rsa)
pub fn sign(key: &RsaKey, prefix: &HashPrefix, digest: &[u8]) -> Result<Vec<u8>, PkeyError> {
    if !key.is_private() { return Err(PkeyError::NoPrivateKey); }
    if !prefix.accepts_digest_len(digest.len()) { return Err(PkeyError::Invalid); }
    let k = key.size();
    if digest.len() + prefix.data.len() + V15_OVERHEAD > k { return Err(PkeyError::Overflow); }
    let ps_len = k - digest.len() - prefix.data.len() - 3;
    let mut em: Vec<u8> = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x01);
    em.extend(core::iter::repeat(0xff).take(ps_len));
    em.push(0x00);
    em.extend_from_slice(prefix.data);
    em.extend_from_slice(digest);
    key.private_op(&em)
}

/// EMSA-PKCS1-v1_5 signature verification.
///
/// The three failures are deliberately distinct: a block that is not a v1.5
/// signature at all is malformed, a well-formed block whose digest does not
/// match is a REJECTED key, and a length that could never have produced this
/// encoding is invalid. A caller that treats "wrong signature" as "corrupt
/// blob" cannot tell an attack from a bug. # C: O(k + rsa)
pub fn verify(key: &RsaKey, prefix: &HashPrefix, sig: &[u8], digest: &[u8])
    -> Result<(), PkeyError>
{
    let k = key.size();
    if sig.len() != k || !prefix.accepts_digest_len(digest.len()) { return Err(PkeyError::Invalid); }
    let em = key.public_op(sig)?;
    if em[0] != 0x00 || em[1] != 0x01 { return Err(PkeyError::BadMessage); }
    let mut pos = 2;
    while pos < em.len() && em[pos] == 0xff { pos += 1; }
    if pos < 2 + MIN_PS || pos == em.len() || em[pos] != 0x00 { return Err(PkeyError::BadMessage); }
    pos += 1;
    if prefix.data.len() > em.len() - pos { return Err(PkeyError::BadMessage); }
    if &em[pos..pos + prefix.data.len()] != prefix.data { return Err(PkeyError::BadMessage); }
    pos += prefix.data.len();
    if digest.len() != em.len() - pos { return Err(PkeyError::Rejected); }
    if &em[pos..] != digest { return Err(PkeyError::Rejected); }
    Ok(())
}
