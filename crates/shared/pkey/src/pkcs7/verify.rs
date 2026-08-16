// Verifying a detached PKCS#7 signature over data the caller supplies.
//
// Two independent questions are answered, in this order, and neither answers
// the other:
//
// - Is the message internally consistent? The digest it claims for the
//   content must be the content's digest, and every certificate link it
//   asserts must hold. A message can pass this and still be worthless.
// - Does it reach a key already trusted? That is `trust`, and it is the only
//   step that makes a signature mean anything.

use alloc::vec::Vec;

use crypt::Digest;

use crate::key::{AsymmetricKey, ENCODING_PKCS1};

use super::certid;
use super::chain::{self, Links};
use super::parse::{self, Message, Signer};
use super::trust::TrustStore;
use super::Pkcs7Error;

/// The identifier octet a `SET OF` carries. The signed attributes are encoded
/// under a context tag but SIGNED as a set, so the one byte is rewritten
/// before hashing. Getting this wrong produces a digest that never matches
/// any signature, on every message that carries attributes.
const TAG_SET: u8 = 0x31;

/// Verify `signature` over `data`, requiring the chain to reach `store`.
///
/// The data is detached: a message that carries its own content is refused
/// rather than verified against the content it brought, which would make the
/// signature attest to something the caller never asked about.
/// # C: O(data + chain * rsa)
pub fn detached(data: &[u8], signature: &[u8], store: &TrustStore)
    -> Result<(), Pkcs7Error> {
    let msg = parse::message(signature)?;
    if msg.has_content { return Err(Pkcs7Error::BadMessage); }
    // The encapsulated type is part of what was signed. A signature over
    // some other type is a valid signature over a different statement.
    if !msg.is_data { return Err(Pkcs7Error::KeyRejected); }

    // Both passes run over every signer before either verdict is taken, so
    // one signer's missing algorithm cannot mask another's bad signature.
    let mut checked: Vec<Checked> = Vec::with_capacity(msg.signers.len());
    let mut supported = false;
    for signer in &msg.signers {
        match one(&msg, signer, data) {
            Ok(c) => { supported = true; checked.push(c); }
            // A signer this build cannot compute is skipped, not fatal:
            // another signer on the same message may be verifiable.
            Err(Pkcs7Error::NoPackage) => checked.push(Checked::unsupported()),
            Err(e) => return Err(e),
        }
    }
    if !supported { return Err(Pkcs7Error::NoPackage); }

    let mut verdict = Err(Pkcs7Error::NoKey);
    for (signer, c) in msg.signers.iter().zip(checked.iter()) {
        let links = match c.links.as_ref() { None => continue, Some(l) => l };
        match super::trust::validate(&msg, signer, c.signer_cert, links, &c.digest, store) {
            Ok(()) => verdict = Ok(()),
            Err(Pkcs7Error::NoKey) => continue,
            Err(e) => return Err(e),
        }
    }
    verdict
}

/// What one signer contributed once its own consistency was checked.
struct Checked {
    /// The digest the signature is over: the content's, or the signed
    /// attributes' when the message carries them.
    digest: Vec<u8>,
    signer_cert: Option<usize>,
    /// `None` for a signer whose algorithms this build has no implementation
    /// of, which is skipped rather than failing the whole message.
    links: Option<Links>,
}

impl Checked {
    fn unsupported() -> Self {
        Self { digest: Vec::new(), signer_cert: None, links: None }
    }
}

/// One signer: what it says the content hashes to, and whether the
/// certificate it names really produced its signature.
/// # C: O(data + chain * rsa)
fn one(msg: &Message<'_>, signer: &Signer<'_>, data: &[u8]) -> Result<Checked, Pkcs7Error> {
    let digest = signed_digest(signer, data)?;
    let signer_cert = find_signer(msg, signer);
    let links = match signer_cert {
        None => Links { issuer_of: alloc::vec![None; msg.certs.len()], authority: Vec::new() },
        Some(i) => {
            // The certificate the message names must have produced the
            // signature before the chain above it is worth walking.
            let key = AsymmetricKey::parse(&msg.certs[i].der)?;
            key.verify(ENCODING_PKCS1, Some(signer.digest), &digest, &signer.signature)
                .map_err(|_| Pkcs7Error::KeyRejected)?;
            chain::build(&msg.certs, i)?
        }
    };
    Ok(Checked { digest, signer_cert, links: Some(links) })
}

/// The digest a signature is actually over.
///
/// With no signed attributes it is the content's digest. With them, the
/// attributes are what is signed, and one of them carries the content's
/// digest — so the content is bound to the signature only if that attribute
/// is checked. Skipping the check would let a valid signature over one file's
/// attributes be replayed onto any other file.
/// # C: O(data)
fn signed_digest(signer: &Signer<'_>, data: &[u8]) -> Result<Vec<u8>, Pkcs7Error> {
    let alg = Digest::by_name(signer.digest).ok_or(Pkcs7Error::NoPackage)?;
    let content = alg.digest(&[data]);
    let attrs = match signer.authattrs { None => return Ok(content), Some(a) => a };
    let claimed = signer.msgdigest.ok_or(Pkcs7Error::BadMessage)?;
    if claimed.len() != content.len() { return Err(Pkcs7Error::BadMessage); }
    if claimed != content.as_slice() { return Err(Pkcs7Error::KeyRejected); }
    let mut set = attrs.to_vec();
    set[0] = TAG_SET;
    Ok(alg.digest(&[&set]))
}

/// The certificate in the message that the signer names.
///
/// A signer identified by a subject key identifier names no certificate this
/// way: the identifier form and the certificate's own naming are different
/// records, so such a signer is left without an in-message certificate and
/// reaches its key through the trust store directly.
/// # C: O(certificates)
fn find_signer(msg: &Message<'_>, signer: &Signer<'_>) -> Option<usize> {
    if signer.skid.is_some() { return None; }
    msg.certs.iter().position(|c| certid::named_by(&c.cert, &signer.issuer, &signer.serial))
}
