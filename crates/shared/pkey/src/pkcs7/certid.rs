// Naming a certificate, and naming the certificate that signed it.
//
// A chain is walked by identity, and a certificate can be named two ways: by
// the issuer name plus the serial number the issuer allocated, or by the key
// identifier its own extension carries. Both are needed, because a signer may
// reference its issuer by either and a keyring may hold it under either.

use alloc::vec::Vec;

use crate::der::{self, Reader};
use crate::x509::Certificate;

use super::oids;
use super::Pkcs7Error;

/// Tag of the `[3] extensions` field of a certificate body.
const TAG_EXTENSIONS: u8 = 0xa3;
/// `[0] IMPLICIT` key identifier inside an authority key identifier.
const TAG_AKID_KEYID: u8 = 0x80;
/// `[1] IMPLICIT` general names naming the authority's own issuer.
const TAG_AKID_ISSUER: u8 = 0xa1;
/// `[2] IMPLICIT` the authority certificate's serial number.
const TAG_AKID_SERIAL: u8 = 0x82;
/// `[4] EXPLICIT` directoryName inside a GeneralName.
const TAG_GN_DIRECTORY: u8 = 0xa4;

/// What a certificate says about the certificate above it.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Authority {
    /// The issuer's subject key identifier.
    pub keyid: Option<Vec<u8>>,
    /// The issuer's own issuer name and the serial it was given.
    pub issuer: Option<Vec<u8>>,
    pub serial: Option<Vec<u8>>,
}

impl Authority {
    /// Whether the extension named the issuer at all. A certificate that names
    /// no authority can only be a root. # C: O(1)
    pub fn is_empty(&self) -> bool {
        self.keyid.is_none() && !(self.issuer.is_some() && self.serial.is_some())
    }
}

/// Whether `c` is the certificate an issuer-and-serial pair names. # C: O(1)
pub fn named_by(c: &Certificate, issuer: &[u8], serial: &[u8]) -> bool {
    c.issuer == issuer && c.serial == serial
}

/// Whether `c` carries this subject key identifier. # C: O(1)
pub fn has_skid(c: &Certificate, skid: &[u8]) -> bool {
    c.skid.as_deref() == Some(skid)
}

/// Read the authority key identifier out of a certificate's signed body.
///
/// The body is re-walked rather than carried alongside the parsed certificate
/// because only a chain walk needs it, and a certificate with no such
/// extension is a normal certificate rather than a malformed one.
/// # C: O(extensions)
pub fn authority(tbs_der: &[u8]) -> Result<Authority, Pkcs7Error> {
    let tbs = der::parse_exact(tbs_der, der::TAG_SEQUENCE)?;
    let mut r = Reader::new(tbs);
    let ext_seq = loop {
        match r.peek_tag() {
            None => return Ok(Authority::default()),
            Some(TAG_EXTENSIONS) => {
                break der::parse_exact(r.expect(TAG_EXTENSIONS)?, der::TAG_SEQUENCE)?;
            }
            Some(_) => { r.next()?; }
        }
    };
    let mut er = Reader::new(ext_seq);
    while !er.is_empty() {
        let ext = er.expect(der::TAG_SEQUENCE)?;
        let mut x = Reader::new(ext);
        let id = x.expect(der::TAG_OID)?;
        x.take_if(der::TAG_BOOLEAN)?;              // critical
        let value = x.expect(der::TAG_OCTET_STRING)?;
        if id == oids::AUTHORITY_KEY_IDENTIFIER {
            return akid(der::parse_exact(value, der::TAG_SEQUENCE)?);
        }
    }
    Ok(Authority::default())
}

/// `AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OPTIONAL,
/// authorityCertIssuer [1] OPTIONAL, authorityCertSerialNumber [2] OPTIONAL }`.
/// # C: O(len)
fn akid(seq: &[u8]) -> Result<Authority, Pkcs7Error> {
    let mut a = Authority::default();
    let mut r = Reader::new(seq);
    if let Some(k) = r.take_if(TAG_AKID_KEYID)? { a.keyid = Some(k.to_vec()); }
    if let Some(names) = r.take_if(TAG_AKID_ISSUER)? {
        // The general name that identifies a certificate authority is a
        // directory name; any other form names something this walk cannot
        // follow, so it is left absent rather than guessed at.
        let mut n = Reader::new(names);
        while !n.is_empty() {
            let (tlv, _) = n.next_raw()?;
            if tlv.tag == TAG_GN_DIRECTORY {
                a.issuer = Some(der::parse_exact(tlv.value, der::TAG_SEQUENCE)?.to_vec());
                break;
            }
        }
    }
    if let Some(s) = r.take_if(TAG_AKID_SERIAL)? {
        a.serial = Some(der::positive_integer(s)?.to_vec());
    }
    Ok(a)
}
