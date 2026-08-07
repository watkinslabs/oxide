// Object identifiers, as the content octets of their DER encoding — comparing
// encoded bytes avoids a decode step that could disagree with the encoder.

/// `rsaEncryption` (1.2.840.113549.1.1.1).
pub const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
pub const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
/// `id-at-commonName` (2.5.4.3).
pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// `id-at-organizationName` (2.5.4.10).
pub const ORGANIZATION_NAME: &[u8] = &[0x55, 0x04, 0x0a];
/// `emailAddress` (1.2.840.113549.1.9.1).
pub const EMAIL_ADDRESS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
/// `id-ce-subjectKeyIdentifier` (2.5.29.14).
pub const SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x0e];

/// The public-key algorithm an identifier names, spelled as the key's
/// algorithm string. `None` for an algorithm this kernel has no
/// implementation of — reported as a missing package, never guessed at.
/// # C: O(1)
pub fn pkey_algo(oid: &[u8]) -> Option<&'static str> {
    if oid == RSA_ENCRYPTION { Some("rsa") } else { None }
}
