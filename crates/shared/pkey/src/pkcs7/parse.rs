// Decoding a PKCS#7 / CMS SignedData into the pieces verification needs.
//
// Nothing here decides trust and nothing here hashes: a parse failure means
// the blob is not a SignedData, which is a different answer from "this is a
// SignedData and the signature is wrong". Keeping the two apart is what lets
// a caller tell a corrupt file from an attack.

use alloc::vec::Vec;

use crate::der::{self, Reader};
use crate::x509;

use super::oids;
use super::Pkcs7Error;

/// `[0] IMPLICIT` — the certificate set in a SignedData, and the signed
/// attributes in a SignerInfo.
pub const TAG_CONT0: u8 = 0xa0;
/// `[1] IMPLICIT` — the revocation list, and the unsigned attributes.
pub const TAG_CONT1: u8 = 0xa1;
/// `[0] IMPLICIT OCTET STRING` — a SignerIdentifier given as a subject key
/// identifier rather than an issuer and serial number.
pub const TAG_SKID_CHOICE: u8 = 0x80;

/// The SignedData versions this decodes: 1 is PKCS#7 and CMS v1, 3 is CMS v3.
pub const VERSION_V1: u8 = 1;
pub const VERSION_V3: u8 = 3;

/// A certificate carried inside the message, kept beside the bytes it was
/// decoded from because verifying a link in the chain needs the key, and the
/// key is parsed from the whole certificate rather than from its fields.
pub struct MsgCert {
    pub der: Vec<u8>,
    pub cert: x509::Certificate,
}

/// One SignerInfo.
pub struct Signer<'a> {
    pub version: u8,
    /// Issuer name content octets, empty when the signer is identified by a
    /// subject key identifier instead.
    pub issuer: Vec<u8>,
    pub serial: Vec<u8>,
    pub skid: Option<Vec<u8>>,
    /// Digest the content was hashed with.
    pub digest: &'static str,
    /// The signed attributes exactly as encoded, HEADER INCLUDED. The header
    /// is needed because what is signed is the same octets re-tagged as a
    /// `SET OF`, so the region cannot be reassembled from its contents.
    pub authattrs: Option<&'a [u8]>,
    /// The `messageDigest` attribute's octets, when the attributes are
    /// present.
    pub msgdigest: Option<&'a [u8]>,
    pub signature: Vec<u8>,
}

/// A decoded SignedData.
pub struct Message<'a> {
    pub version: u8,
    /// Whether the encapsulated type is `pkcs7-data`.
    pub is_data: bool,
    /// Whether the message carries the content it signs. A built-in signature
    /// is detached, and one that carries content signs something other than
    /// the data the caller supplied.
    pub has_content: bool,
    pub certs: Vec<MsgCert>,
    pub signers: Vec<Signer<'a>>,
}

/// Decode a `ContentInfo` wrapping a `SignedData`. # C: O(len)
pub fn message(blob: &[u8]) -> Result<Message<'_>, Pkcs7Error> {
    let ci = der::parse_exact(blob, der::TAG_SEQUENCE)?;
    let mut r = Reader::new(ci);
    if r.expect(der::TAG_OID)? != oids::SIGNED_DATA { return Err(Pkcs7Error::BadMessage); }
    let content = r.expect(TAG_CONT0)?;
    r.end()?;
    signed_data(der::parse_exact(content, der::TAG_SEQUENCE)?)
}

/// `SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
/// certificates [0] OPTIONAL, crls [1] OPTIONAL, signerInfos }`. # C: O(len)
fn signed_data(sd: &[u8]) -> Result<Message<'_>, Pkcs7Error> {
    let mut r = Reader::new(sd);
    let version = small_int(r.expect(der::TAG_INTEGER)?)?;
    if version != VERSION_V1 && version != VERSION_V3 { return Err(Pkcs7Error::BadMessage); }
    r.expect(der::TAG_SET)?;                       // digestAlgorithms
    let (is_data, has_content) = encap(r.expect(der::TAG_SEQUENCE)?)?;
    let certs = match r.take_if(TAG_CONT0)? {
        None => Vec::new(),
        Some(set) => certificates(set)?,
    };
    r.take_if(TAG_CONT1)?;                         // crls, unused
    let signers = signer_infos(r.expect(der::TAG_SET)?, version)?;
    r.end()?;
    if signers.is_empty() { return Err(Pkcs7Error::BadMessage); }
    Ok(Message { version, is_data, has_content, certs, signers })
}

/// `EncapsulatedContentInfo ::= SEQUENCE { eContentType, eContent [0] EXPLICIT
/// OPTIONAL }`. # C: O(1)
fn encap(seq: &[u8]) -> Result<(bool, bool), Pkcs7Error> {
    let mut r = Reader::new(seq);
    let ty = r.expect(der::TAG_OID)?;
    let has_content = r.take_if(TAG_CONT0)?.is_some();
    r.end()?;
    Ok((ty == oids::DATA, has_content))
}

/// The certificate set. A member this decoder cannot read is skipped rather
/// than fatal: a chain may carry an attribute certificate beside the X.509
/// ones, and the signer's own certificate may still be present.
/// # C: O(certificates)
fn certificates(set: &[u8]) -> Result<Vec<MsgCert>, Pkcs7Error> {
    let mut out = Vec::new();
    let mut r = Reader::new(set);
    while !r.is_empty() {
        let (tlv, raw) = r.next_raw()?;
        if tlv.tag != der::TAG_SEQUENCE { continue; }
        if let Ok(cert) = x509::parse(raw) { out.push(MsgCert { der: raw.to_vec(), cert }); }
    }
    Ok(out)
}

/// The signer set. # C: O(len)
fn signer_infos(set: &[u8], msg_version: u8) -> Result<Vec<Signer<'_>>, Pkcs7Error> {
    let mut out = Vec::new();
    let mut r = Reader::new(set);
    while !r.is_empty() {
        out.push(signer_info(r.expect(der::TAG_SEQUENCE)?, msg_version)?);
    }
    Ok(out)
}

/// One `SignerInfo`. # C: O(len)
fn signer_info(si: &[u8], msg_version: u8) -> Result<Signer<'_>, Pkcs7Error> {
    let mut r = Reader::new(si);
    let version = small_int(r.expect(der::TAG_INTEGER)?)?;
    // The identifier form is fixed by the version pair, not chosen freely: a
    // v1 signer names an issuer and serial, a v3 signer names a subject key
    // identifier, and a message and its signers may not disagree about which.
    let (issuer, serial, skid) = match version {
        VERSION_V1 => {
            if msg_version != VERSION_V1 { return Err(Pkcs7Error::BadMessage); }
            let (i, s) = issuer_and_serial(r.expect(der::TAG_SEQUENCE)?)?;
            (i, s, None)
        }
        VERSION_V3 => {
            if msg_version == VERSION_V1 { return Err(Pkcs7Error::BadMessage); }
            (Vec::new(), Vec::new(), Some(r.expect(TAG_SKID_CHOICE)?.to_vec()))
        }
        _ => return Err(Pkcs7Error::BadMessage),
    };
    let digest = algorithm(r.expect(der::TAG_SEQUENCE)?, oids::digest_name)?;
    let (authattrs, msgdigest) = match peek_raw(&mut r, TAG_CONT0)? {
        None => (None, None),
        Some((value, raw)) => (Some(raw), Some(attributes(value)?)),
    };
    algorithm(r.expect(der::TAG_SEQUENCE)?, |o| {
        // The signature algorithm may name the key algorithm alone
        // (`rsaEncryption`) or the pair; either way the digest is the one the
        // SignerInfo already declared, so only the key algorithm matters here.
        if o == crate::oid::RSA_ENCRYPTION || oids::signature_digest_name(o).is_some() {
            Some("rsa")
        } else { None }
    })?;
    let signature = r.expect(der::TAG_OCTET_STRING)?.to_vec();
    r.take_if(TAG_CONT1)?;                         // unsignedAttrs, not signed
    r.end()?;
    Ok(Signer { version, issuer, serial, skid, digest, authattrs, msgdigest, signature })
}

/// `IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }`.
/// # C: O(1)
fn issuer_and_serial(seq: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Pkcs7Error> {
    let mut r = Reader::new(seq);
    let issuer = r.expect(der::TAG_SEQUENCE)?.to_vec();
    let serial = der::positive_integer(r.expect(der::TAG_INTEGER)?)?.to_vec();
    r.end()?;
    Ok((issuer, serial))
}

/// An `AlgorithmIdentifier`, resolved through `name`. An absent parameters
/// field and an explicit NULL are the same algorithm. # C: O(1)
fn algorithm<F>(seq: &[u8], name: F) -> Result<&'static str, Pkcs7Error>
where F: Fn(&[u8]) -> Option<&'static str> {
    let mut r = Reader::new(seq);
    let oid = r.expect(der::TAG_OID)?;
    name(oid).ok_or(Pkcs7Error::NoPackage)
}

/// The signed attributes: the two that must be present are checked here, so a
/// set missing one is refused before any hashing happens. Returns the
/// `messageDigest` octets. # C: O(attributes)
fn attributes(set: &[u8]) -> Result<&[u8], Pkcs7Error> {
    let (mut content_type, mut digest) = (false, None);
    let mut r = Reader::new(set);
    while !r.is_empty() {
        let attr = r.expect(der::TAG_SEQUENCE)?;
        let mut a = Reader::new(attr);
        let id = a.expect(der::TAG_OID)?;
        let values = a.expect(der::TAG_SET)?;
        a.end()?;
        let mut v = Reader::new(values);
        if id == oids::CONTENT_TYPE {
            // One value per attribute, never a multivalue set: a second value
            // is a second claim about what was signed.
            if content_type { return Err(Pkcs7Error::KeyRejected); }
            v.expect(der::TAG_OID)?;
            v.end()?;
            content_type = true;
        } else if id == oids::MESSAGE_DIGEST {
            if digest.is_some() { return Err(Pkcs7Error::KeyRejected); }
            digest = Some(v.expect(der::TAG_OCTET_STRING)?);
            v.end()?;
        }
    }
    if !content_type { return Err(Pkcs7Error::BadMessage); }
    digest.ok_or(Pkcs7Error::BadMessage)
}

/// An element's contents and its whole encoding, header included.
type Element<'a> = (&'a [u8], &'a [u8]);

/// Take the next element only if it carries `tag`, returning both.
/// # C: O(1)
fn peek_raw<'a>(r: &mut Reader<'a>, tag: u8) -> Result<Option<Element<'a>>, Pkcs7Error> {
    if r.peek_tag() != Some(tag) { return Ok(None); }
    let (tlv, raw) = r.next_raw()?;
    Ok(Some((tlv.value, raw)))
}

/// A version number, which is one octet in every form this decodes. # C: O(1)
fn small_int(v: &[u8]) -> Result<u8, Pkcs7Error> {
    match v {
        [b] => Ok(*b),
        _ => Err(Pkcs7Error::BadMessage),
    }
}
