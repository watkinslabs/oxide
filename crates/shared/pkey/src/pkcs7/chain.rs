// The certificate chain a message carries, verified as far as it goes.
//
// This proves only that the certificates inside the message are consistent
// with each other — that each one really was signed by the one it names. It
// says nothing about trust: a message can carry a perfectly self-consistent
// chain rooted in a certificate nobody has ever heard of. Trust is the
// separate question of whether the chain reaches a key already held, and it
// is answered in `trust`.

use alloc::vec::Vec;

use crate::key::AsymmetricKey;

use super::certid::{self, Authority};
use super::parse::MsgCert;
use super::Pkcs7Error;

/// Where each certificate's issuer is, once the links have been checked.
pub struct Links {
    /// For each certificate, the index of the certificate that signed it. A
    /// self-signed certificate points at itself; `None` means the issuer is
    /// not in this message, so the chain stops there.
    pub issuer_of: Vec<Option<usize>>,
    /// Each certificate's authority extension, decoded once.
    pub authority: Vec<Authority>,
}

/// Verify the chain reachable from `start`, recording where each link leads.
///
/// A link whose issuer is absent from the message ends the walk without
/// error: the missing certificate may still be one the caller already trusts,
/// and refusing here would reject exactly the chains that are shortest to
/// validate. A link whose issuer IS present and whose signature does not
/// verify is fatal, because the message asserted a relationship that is false.
/// # C: O(chain length * rsa)
pub fn build(certs: &[MsgCert], start: usize) -> Result<Links, Pkcs7Error> {
    let mut authority = Vec::with_capacity(certs.len());
    for c in certs { authority.push(certid::authority(&c.cert.tbs)?); }
    let mut issuer_of: Vec<Option<usize>> = alloc::vec![None; certs.len()];
    let mut seen = alloc::vec![false; certs.len()];
    let mut at = start;
    loop {
        if seen[at] { return Ok(Links { issuer_of, authority }); }
        seen[at] = true;
        if self_signed(&certs[at], &authority[at])? {
            issuer_of[at] = Some(at);
            return Ok(Links { issuer_of, authority });
        }
        let found = match find_issuer(certs, &authority[at]) {
            Err(e) => return Err(e),
            Ok(None) => return Ok(Links { issuer_of, authority }),
            Ok(Some(i)) => i,
        };
        // The issuer's key must actually have produced this certificate's
        // signature. Accepting the naming alone would let a message claim any
        // certificate as the parent of any other.
        let key = AsymmetricKey::parse(&certs[found].der)?;
        key.verify_certificate(&certs[at].cert)?;
        issuer_of[at] = Some(found);
        if found == at { return Ok(Links { issuer_of, authority }); }
        at = found;
    }
}

/// Whether a certificate is its own issuer, which makes it the root of a
/// chain of its own.
///
/// Matching names is not enough: the authority extension, if it names one,
/// must name this certificate, and the certificate must really carry its own
/// signature. Treating an unverified name match as a root would let a
/// forged certificate end a chain wherever it liked.
/// # C: O(rsa)
fn self_signed(c: &MsgCert, auth: &Authority) -> Result<bool, Pkcs7Error> {
    if c.cert.subject_id != c.cert.issuer { return Ok(false); }
    if !auth.is_empty() {
        let by_keyid = match auth.keyid.as_ref() {
            Some(k) => certid::has_skid(&c.cert, k),
            None => false,
        };
        let by_name = match (auth.issuer.as_ref(), auth.serial.as_ref()) {
            (Some(i), Some(s)) => certid::named_by(&c.cert, i, s),
            _ => false,
        };
        if !by_keyid && !by_name { return Ok(false); }
        // Both forms supplied and only one agreeing is a contradiction in the
        // certificate itself, not a partial match to accept.
        let both_given = auth.keyid.is_some() && auth.issuer.is_some() && auth.serial.is_some();
        if both_given && by_keyid != by_name { return Err(Pkcs7Error::KeyRejected); }
    }
    AsymmetricKey::parse(&c.der)?.verify_certificate(&c.cert)?;
    Ok(true)
}

/// Which certificate in the message issued this one.
///
/// The issuer name and serial the authority extension gives come first,
/// because that pair names one certificate exactly; the key identifier is the
/// form a chain uses when it names its authority only that way. When both are
/// given, the named certificate's key identifier must also agree — a mismatch
/// is a message asserting two different parents, not a near miss. A
/// certificate naming no authority at all ends the walk: there is nothing to
/// look up, and matching on the issuer name alone would follow a link the
/// certificate never asserted.
/// # C: O(certificates)
fn find_issuer(certs: &[MsgCert], auth: &Authority) -> Result<Option<usize>, Pkcs7Error> {
    let (issuer, serial) = match (auth.issuer.as_ref(), auth.serial.as_ref()) {
        (Some(i), Some(s)) => (i.as_slice(), s.as_slice()),
        _ => {
            return Ok(match auth.keyid.as_ref() {
                Some(k) => certs.iter().position(|c| certid::has_skid(&c.cert, k)),
                None => None,
            });
        }
    };
    match certs.iter().position(|c| certid::named_by(&c.cert, issuer, serial)) {
        None => Ok(None),
        Some(i) => {
            if let Some(k) = auth.keyid.as_ref() {
                if !certid::has_skid(&certs[i].cert, k) { return Err(Pkcs7Error::KeyRejected); }
            }
            Ok(Some(i))
        }
    }
}
