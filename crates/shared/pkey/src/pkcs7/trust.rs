// Whether a message's chain reaches a key that is already trusted.
//
// The certificates inside a message prove nothing on their own — anyone can
// mint a chain. Trust is the separate question of whether that chain
// intersects keys held outside the message, and the answer is not "a name
// matches" but "a key we already hold produced a signature in this chain".
// Every match below is therefore followed by a signature check.

use alloc::vec::Vec;

use crate::key::AsymmetricKey;

use super::certid;
use super::chain::Links;
use super::parse::{Message, MsgCert, Signer};
use super::Pkcs7Error;

/// The certificates a caller already trusts. Empty is a meaningful state and
/// not an error here: the caller decides what an empty store means, because
/// for some callers it is a configuration that rejects every signed file.
#[derive(Default)]
pub struct TrustStore {
    certs: Vec<MsgCert>,
}

impl TrustStore {
    /// # C: O(1)
    pub fn new() -> Self { Self { certs: Vec::new() } }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.certs.is_empty() }

    /// # C: O(1)
    pub fn len(&self) -> usize { self.certs.len() }

    /// Add a DER certificate. # C: O(len)
    pub fn add(&mut self, der: &[u8]) -> Result<(), Pkcs7Error> {
        let cert = crate::x509::parse(der)?;
        self.certs.push(MsgCert { der: der.to_vec(), cert });
        Ok(())
    }

    /// The trusted certificate an issuer-and-serial pair names, with the key
    /// identifier required to agree when one is given. # C: O(certificates)
    fn by_name(&self, issuer: &[u8], serial: &[u8], skid: Option<&[u8]>) -> Option<&MsgCert> {
        self.certs.iter().find(|c| {
            certid::named_by(&c.cert, issuer, serial)
                && match skid { None => true, Some(k) => certid::has_skid(&c.cert, k) }
        })
    }

    /// The trusted certificate a key identifier names. # C: O(certificates)
    fn by_skid(&self, skid: &[u8]) -> Option<&MsgCert> {
        self.certs.iter().find(|c| certid::has_skid(&c.cert, skid))
    }
}

/// What a trusted key is asked to have signed.
pub enum Target<'a> {
    /// The message signature itself, over an already-computed digest.
    Message { hash: &'static str, digest: &'a [u8], sig: &'a [u8] },
    /// The signature on one of the message's own certificates.
    Cert(usize),
}

/// Walk from the signer towards a trusted key, checking a signature at the
/// point the two meet.
///
/// The chain is climbed in the order the message asserts it, and the FIRST
/// certificate found in the store decides: the trusted copy is then required
/// to have produced whichever signature the walk had reached — the message's
/// own when the signer itself is trusted, or the signature on the certificate
/// below when a certificate authority is. A self-signed certificate that is
/// not in the store ends the walk, because a root nobody holds is a root
/// nobody trusts.
/// # C: O(chain length * rsa)
pub fn validate(msg: &Message<'_>, signer: &Signer<'_>, signer_cert: Option<usize>,
                links: &Links, digest: &[u8], store: &TrustStore)
    -> Result<(), Pkcs7Error> {
    if let (Some(time), Some(index)) = (signer.signing_time, signer_cert) {
        let cert = &msg.certs[index].cert;
        if time < cert.valid_from || time > cert.valid_to { return Err(Pkcs7Error::KeyRejected); }
    }
    let mut at = signer_cert;
    let mut target = Target::Message { hash: signer.digest, digest, sig: &signer.signature };
    let mut last: Option<usize> = None;
    let mut seen = alloc::vec![false; msg.certs.len()];
    while let Some(i) = at {
        if seen[i] { break; }
        seen[i] = true;
        let c = &msg.certs[i].cert;
        if let Some(t) = store.by_name(&c.issuer, &c.serial, c.skid.as_deref()) {
            return check(t, msg, &target);
        }
        // A certificate that signed itself is the top of its chain. If the
        // store does not hold it, nothing above it can be reached.
        if links.issuer_of[i] == Some(i) { return Err(Pkcs7Error::NoKey); }
        last = Some(i);
        target = Target::Cert(i);
        at = links.issuer_of[i];
    }
    // The chain ran out inside the message. The certificate it ran out at may
    // still name an authority the store holds.
    if let Some(i) = last {
        let auth = &links.authority[i];
        let found = match (auth.issuer.as_ref(), auth.serial.as_ref()) {
            (Some(iss), Some(ser)) => store.by_name(iss, ser, auth.keyid.as_deref()),
            _ => auth.keyid.as_deref().and_then(|k| store.by_skid(k)),
        };
        if let Some(t) = found { return check(t, msg, &Target::Cert(i)); }
    }
    // Last resort: the store may hold the signer's key directly, even though
    // the message carried no certificate for it.
    let direct = if signer.skid.is_some() {
        signer.skid.as_deref().and_then(|k| store.by_skid(k))
    } else {
        store.by_name(&signer.issuer, &signer.serial, None)
    };
    match direct {
        Some(t) => check(t, msg, &Target::Message {
            hash: signer.digest, digest, sig: &signer.signature,
        }),
        None => Err(Pkcs7Error::NoKey),
    }
}

/// Require the trusted key to have produced the signature the walk reached.
/// A match on identity alone is not trust — it is the claim that trust is
/// being asserted about. # C: O(rsa)
fn check(trusted: &MsgCert, msg: &Message<'_>, target: &Target<'_>) -> Result<(), Pkcs7Error> {
    let key = AsymmetricKey::parse(&trusted.der)?;
    let ok = match target {
        Target::Message { hash, digest, sig } => {
            key.verify(crate::key::ENCODING_PKCS1, Some(hash), digest, sig)
        }
        Target::Cert(i) => key.verify_certificate(&msg.certs[*i].cert),
    };
    ok.map_err(|_| Pkcs7Error::KeyRejected)
}
