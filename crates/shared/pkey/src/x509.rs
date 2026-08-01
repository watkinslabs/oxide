// X.509 certificate parsing — enough of the structure to reach the public key
// and to name the certificate the way the key subsystem names it. The
// signature on the certificate is not checked here: an asymmetric key is
// trusted because of the keyring it was linked into, not because it carries a
// self-consistent signature.

use alloc::string::String;
use alloc::vec::Vec;

use crate::der::{self, Reader, DerError};
use crate::oid;
use crate::PkeyError;

/// Tag of the `[3] extensions` field of a certificate body.
const TAG_EXTENSIONS: u8 = 0xa3;
/// Tag of the `[0] version` field.
const TAG_VERSION: u8 = 0xa0;
/// The prefix length two names are compared over when deciding whether an
/// organization name is already carried by the common name.
const NAME_PREFIX_MATCH: usize = 7;

/// What a certificate contributes to a key.
pub struct Certificate {
    /// The rendered subject name, as the key description carries it.
    pub subject: String,
    /// Raw `serialNumber` content octets.
    pub serial: Vec<u8>,
    /// Raw subject key identifier, when the certificate carries one.
    pub skid: Option<Vec<u8>>,
    /// Public-key algorithm name.
    pub algo: &'static str,
    /// The `subjectPublicKey` contents — for RSA, an `RSAPublicKey`.
    pub key: Vec<u8>,
}

/// Parse a DER certificate. # C: O(len)
pub fn parse(blob: &[u8]) -> Result<Certificate, PkeyError> {
    let cert = der::parse_exact(blob, der::TAG_SEQUENCE)?;
    let mut top = Reader::new(cert);
    let tbs = top.expect(der::TAG_SEQUENCE)?;
    // The signature algorithm and value follow; they are read only to prove
    // the certificate is structurally whole.
    top.expect(der::TAG_SEQUENCE)?;
    der::bit_string_bytes(top.expect(der::TAG_BIT_STRING)?)?;
    top.end()?;

    let mut r = Reader::new(tbs);
    r.take_if(TAG_VERSION)?;
    let serial = der::positive_integer(r.expect(der::TAG_INTEGER)?)?.to_vec();
    r.expect(der::TAG_SEQUENCE)?;          // inner signature algorithm
    r.expect(der::TAG_SEQUENCE)?;          // issuer
    r.expect(der::TAG_SEQUENCE)?;          // validity
    let subject_raw = r.expect(der::TAG_SEQUENCE)?;
    let spki = r.expect(der::TAG_SEQUENCE)?;

    let (algo, key) = parse_spki(spki)?;
    let subject = render_name(subject_raw)?;
    let skid = find_skid(&mut r)?;
    Ok(Certificate { subject, serial, skid, algo, key })
}

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
/// subjectPublicKey BIT STRING }`. # C: O(len)
fn parse_spki(spki: &[u8]) -> Result<(&'static str, Vec<u8>), PkeyError> {
    let mut r = Reader::new(spki);
    let alg = r.expect(der::TAG_SEQUENCE)?;
    let mut ar = Reader::new(alg);
    let algo_oid = ar.expect(der::TAG_OID)?;
    let algo = oid::pkey_algo(algo_oid).ok_or(PkeyError::NoPackage)?;
    let key = der::bit_string_bytes(r.expect(der::TAG_BIT_STRING)?)?.to_vec();
    Ok((algo, key))
}

/// Walk the optional trailing fields for the extensions, and the extensions
/// for a subject key identifier. An extension this kernel does not act on is
/// skipped, including one marked critical: acting on the key requires reading
/// the key, not honouring a policy the certificate asks a validator to apply.
/// # C: O(extensions)
fn find_skid(r: &mut Reader<'_>) -> Result<Option<Vec<u8>>, PkeyError> {
    let ext_seq = loop {
        match r.peek_tag() {
            None => return Ok(None),
            Some(TAG_EXTENSIONS) => break der::parse_exact(r.expect(TAG_EXTENSIONS)?, der::TAG_SEQUENCE)?,
            Some(_) => { r.next()?; }
        }
    };
    let mut er = Reader::new(ext_seq);
    while !er.is_empty() {
        let ext = er.expect(der::TAG_SEQUENCE)?;
        let mut x = Reader::new(ext);
        let id = x.expect(der::TAG_OID)?;
        x.take_if(der::TAG_BOOLEAN)?;      // critical
        let value = x.expect(der::TAG_OCTET_STRING)?;
        if id == oid::SUBJECT_KEY_IDENTIFIER {
            // The extension's value is itself a DER OCTET STRING holding the
            // identifier.
            return Ok(Some(der::parse_exact(value, der::TAG_OCTET_STRING)?.to_vec()));
        }
    }
    Ok(None)
}

/// Render a `Name` the way the key subsystem names a certificate: the common
/// name, the organization name, or both joined — with the organization
/// dropped when the common name already carries it — falling back to the email
/// address, and to the empty string when the name has none of the three.
/// # C: O(len)
fn render_name(name: &[u8]) -> Result<String, PkeyError> {
    let (mut cn, mut o, mut email): (Option<&[u8]>, Option<&[u8]>, Option<&[u8]>) = (None, None, None);
    let mut r = Reader::new(name);
    while !r.is_empty() {
        let rdn = r.expect(der::TAG_SET)?;
        let mut sr = Reader::new(rdn);
        while !sr.is_empty() {
            let ava = sr.expect(der::TAG_SEQUENCE)?;
            let mut ar = Reader::new(ava);
            let id = ar.expect(der::TAG_OID)?;
            let value = ar.next()?.value;
            if id == oid::COMMON_NAME { cn = Some(value); }
            else if id == oid::ORGANIZATION_NAME { o = Some(value); }
            else if id == oid::EMAIL_ADDRESS { email = Some(value); }
        }
    }
    let bytes: Vec<u8> = match (cn, o) {
        (Some(c), Some(org)) => {
            let carried = c.len() >= org.len() && &c[..org.len()] == org;
            let shared_prefix = c.len() >= NAME_PREFIX_MATCH && org.len() >= NAME_PREFIX_MATCH
                && c[..NAME_PREFIX_MATCH] == org[..NAME_PREFIX_MATCH];
            if carried || shared_prefix { c.to_vec() } else {
                let mut v = org.to_vec();
                v.extend_from_slice(b": ");
                v.extend_from_slice(c);
                v
            }
        }
        (Some(c), None) => c.to_vec(),
        (None, Some(org)) => org.to_vec(),
        (None, None) => email.unwrap_or(&[]).to_vec(),
    };
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

impl From<DerError> for PkeyError {
    /// Every decoding failure is one answer to userspace: the blob is not a
    /// certificate. # C: O(1)
    fn from(_: DerError) -> Self { PkeyError::BadMessage }
}
