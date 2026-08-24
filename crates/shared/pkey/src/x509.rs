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
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;

/// What a certificate contributes to a key.
pub struct Certificate {
    /// The rendered subject name, as the key description carries it.
    pub subject: String,
    /// Raw subject-name content octets used as the third key identifier.
    pub subject_id: Vec<u8>,
    /// Raw `serialNumber` content octets.
    pub serial: Vec<u8>,
    /// Raw issuer-name content octets paired with the serial-number ID.
    pub issuer: Vec<u8>,
    /// Raw subject key identifier, when the certificate carries one.
    pub skid: Option<Vec<u8>>,
    /// Public-key algorithm name.
    pub algo: &'static str,
    /// The `subjectPublicKey` contents — for RSA, an `RSAPublicKey`.
    pub key: Vec<u8>,
    /// Full DER encoding of the signed `TBSCertificate`.
    pub tbs: Vec<u8>,
    /// Digest name declared by the certificate signature algorithm.
    pub signature_hash: Option<&'static str>,
    /// Signature octets after the BIT STRING's unused-bit count.
    pub signature: Vec<u8>,
    /// Inclusive validity interval, in Unix seconds.
    pub valid_from: i64,
    pub valid_to: i64,
}

/// Parse a DER certificate.
///
/// Handed back on the heap: the record is ten heap-backed fields and every
/// caller binds it across a verification, so returned by value it sat in the
/// frame of each. The reference keeps a parsed certificate in its own
/// allocation and passes the pointer. # C: O(len)
pub fn parse(blob: &[u8]) -> Result<alloc::boxed::Box<Certificate>, PkeyError> {
    let cert = der::parse_exact(blob, der::TAG_SEQUENCE)?;
    let mut top = Reader::new(cert);
    let (tbs_tlv, tbs_raw) = top.next_raw()?;
    if tbs_tlv.tag != der::TAG_SEQUENCE { return Err(PkeyError::BadMessage); }
    let tbs = tbs_tlv.value;
    let sig_alg = top.expect(der::TAG_SEQUENCE)?;
    let mut sig_alg = Reader::new(sig_alg);
    let sig_oid = sig_alg.expect(der::TAG_OID)?;
    sig_alg.take_if(der::TAG_NULL)?;
    sig_alg.end()?;
    let signature_hash = if sig_oid == oid::SHA256_WITH_RSA { Some("sha256") } else { None };
    let signature = der::bit_string_bytes(top.expect(der::TAG_BIT_STRING)?)?.to_vec();
    top.end()?;

    let mut r = Reader::new(tbs);
    r.take_if(TAG_VERSION)?;
    let serial = der::positive_integer(r.expect(der::TAG_INTEGER)?)?.to_vec();
    r.expect(der::TAG_SEQUENCE)?;          // inner signature algorithm
    let issuer = r.expect(der::TAG_SEQUENCE)?.to_vec();
    let validity = r.expect(der::TAG_SEQUENCE)?;
    let (valid_from, valid_to) = parse_validity(validity)?;
    let subject_raw = r.expect(der::TAG_SEQUENCE)?;
    let spki = r.expect(der::TAG_SEQUENCE)?;

    let (algo, key) = parse_spki(spki)?;
    let subject = render_name(subject_raw)?;
    let skid = find_skid(&mut r)?;
    Ok(alloc::boxed::Box::new(Certificate {
        subject, subject_id: subject_raw.to_vec(), serial, issuer, skid, algo, key,
        tbs: tbs_raw.to_vec(), signature_hash, signature, valid_from, valid_to,
    }))
}

/// Parse `Validity ::= SEQUENCE { notBefore, notAfter }`. # C: O(1)
fn parse_validity(value: &[u8]) -> Result<(i64, i64), PkeyError> {
    let mut r = Reader::new(value);
    let from_tag = r.peek_tag().ok_or(PkeyError::BadMessage)?;
    let from = r.next()?.value;
    let to_tag = r.peek_tag().ok_or(PkeyError::BadMessage)?;
    let to = r.next()?.value;
    r.end()?;
    Ok((parse_time(from_tag, from)?, parse_time(to_tag, to)?))
}

/// Decode the DER time forms accepted by the X.509 profile. # C: O(1)
pub(crate) fn parse_time(tag: u8, value: &[u8]) -> Result<i64, PkeyError> {
    let (year, at) = match tag {
        TAG_UTC_TIME if value.len() == 13 => {
            let yy = two_digits(&value[..2])? as i32;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
        }
        TAG_GENERALIZED_TIME if value.len() == 15 => {
            let y = four_digits(&value[..4])? as i32;
            if (1950..=2049).contains(&y) { return Err(PkeyError::BadMessage); }
            (y, 4)
        }
        _ => return Err(PkeyError::BadMessage),
    };
    if value[value.len() - 1] != b'Z' { return Err(PkeyError::BadMessage); }
    let month = two_digits(&value[at..at + 2])? as i32;
    let day = two_digits(&value[at + 2..at + 4])? as i32;
    let hour = two_digits(&value[at + 4..at + 6])? as i32;
    let min = two_digits(&value[at + 6..at + 8])? as i32;
    let sec = two_digits(&value[at + 8..at + 10])? as i32;
    if year < 1970 || !(1..=12).contains(&month) || hour > 24 || min > 59 || sec > 60 {
        return Err(PkeyError::BadMessage);
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30,
                31, 31, 30, 31, 30, 31];
    if day < 1 || day > days[(month - 1) as usize] { return Err(PkeyError::BadMessage); }
    let mut y = i64::from(year);
    let m = i64::from(month);
    y -= i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_since_epoch = era * 146097 + doe - 719468;
    Ok(days_since_epoch * 86_400 + i64::from(hour) * 3_600
       + i64::from(min) * 60 + i64::from(sec))
}

fn two_digits(value: &[u8]) -> Result<u8, PkeyError> {
    if value.len() != 2 || !value.iter().all(|b| b.is_ascii_digit()) { return Err(PkeyError::BadMessage); }
    Ok((value[0] - b'0') * 10 + value[1] - b'0')
}

fn four_digits(value: &[u8]) -> Result<u16, PkeyError> {
    if value.len() != 4 || !value.iter().all(|b| b.is_ascii_digit()) { return Err(PkeyError::BadMessage); }
    Ok(u16::from(two_digits(&value[..2])?) * 100 + u16::from(two_digits(&value[2..])?))
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
