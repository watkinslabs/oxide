// Object identifiers a PKCS#7 SignedData carries, as the content octets of
// their DER encoding. Comparing encoded bytes is what the decoder already
// produces, so no second encoding step can disagree with the first.

/// `pkcs7-signedData` (1.2.840.113549.1.7.2) — the only ContentInfo type a
/// signature is carried in.
pub const SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// `pkcs7-data` (1.2.840.113549.1.7.1) — the encapsulated type an
/// unspecified-usage signature must declare.
pub const DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];

/// `contentType` (1.2.840.113549.1.9.3), a required signed attribute.
pub const CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
/// `messageDigest` (1.2.840.113549.1.9.4), a required signed attribute.
pub const MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
pub const SIGNING_TIME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05];

/// `id-ce-authorityKeyIdentifier` (2.5.29.35).
pub const AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x23];

/// Digest algorithm identifiers, paired with the name the digest registry
/// knows them by.
const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const SHA224: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];
const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/// The digest an algorithm identifier names. `None` for one this kernel has
/// no implementation of, which is reported as a missing package rather than
/// silently substituted. # C: O(1)
pub fn digest_name(oid: &[u8]) -> Option<&'static str> {
    match oid {
        x if x == SHA1 => Some("sha1"),
        x if x == SHA224 => Some("sha224"),
        x if x == SHA256 => Some("sha256"),
        x if x == SHA384 => Some("sha384"),
        x if x == SHA512 => Some("sha512"),
        _ => None,
    }
}

/// The digest a `<hash>WithRSAEncryption` signature algorithm names.
/// # C: O(1)
pub fn signature_digest_name(oid: &[u8]) -> Option<&'static str> {
    const P: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
    if oid.len() != P.len() + 1 || &oid[..P.len()] != P { return None; }
    match oid[P.len()] {
        0x05 => Some("sha1"),
        0x0b => Some("sha256"),
        0x0c => Some("sha384"),
        0x0d => Some("sha512"),
        0x0e => Some("sha224"),
        _ => None,
    }
}
