// What the decoder reads out of a real message, and the shapes it refuses.

use crate::pkcs7::parse;
use crate::pkcs7::Pkcs7Error;

use super::fixtures::{unhex, SIG_ATTR, SIG_CHAIN, SIG_NOATTR};

#[test]
fn a_detached_message_names_its_signer_and_carries_its_certificate() {
    let der = unhex(SIG_NOATTR);
    let m = parse::message(&der).expect("a real signature decodes");
    assert_eq!(m.version, parse::VERSION_V1);
    assert!(m.is_data);
    // Detached is the whole point: the signature must not bring its own copy
    // of what it signs, or it attests to bytes the caller never supplied.
    assert!(!m.has_content);
    assert_eq!(m.certs.len(), 1);
    assert_eq!(m.signers.len(), 1);
    let s = &m.signers[0];
    assert_eq!(s.digest, "sha256");
    assert!(s.authattrs.is_none());
    assert!(s.msgdigest.is_none());
    // The signer names the certificate by the issuer that minted it, not by
    // the certificate's own subject.
    assert_eq!(s.issuer, m.certs[0].cert.issuer);
    assert_eq!(s.serial, m.certs[0].cert.serial);
    assert_eq!(s.signature.len(), 256);
}

#[test]
fn signed_attributes_are_kept_with_their_header() {
    // What is signed is the attribute region re-tagged as a SET, so the
    // region cannot be rebuilt from its contents — the header must survive
    // the decode.
    let der = unhex(SIG_ATTR);
    let m = parse::message(&der).expect("decodes");
    let s = &m.signers[0];
    let attrs = s.authattrs.expect("this signature carries attributes");
    assert_eq!(attrs[0], parse::TAG_CONT0);
    assert_eq!(s.msgdigest.expect("messageDigest is required").len(), 32);
}

#[test]
fn a_chain_message_carries_every_certificate_in_it() {
    let der = unhex(SIG_CHAIN);
    let m = parse::message(&der).expect("decodes");
    assert_eq!(m.certs.len(), 2);
    // Both are readable, and they are not the same certificate.
    assert_ne!(m.certs[0].cert.subject_id, m.certs[1].cert.subject_id);
}

#[test]
fn a_blob_that_is_not_a_signed_data_is_refused() {
    assert_eq!(parse::message(&[]).err(), Some(Pkcs7Error::BadMessage));
    assert_eq!(parse::message(b"not der at all").err(), Some(Pkcs7Error::BadMessage));
    // A certificate is well-formed DER and is still not a signature.
    let cert = unhex(super::fixtures::LEAF_DER);
    assert_eq!(parse::message(&cert).err(), Some(Pkcs7Error::BadMessage));
}

#[test]
fn a_truncated_message_is_refused_rather_than_read_partially() {
    let der = unhex(SIG_NOATTR);
    for cut in [1usize, 16, der.len() / 2, der.len() - 1] {
        assert_eq!(parse::message(&der[..cut]).err(), Some(Pkcs7Error::BadMessage),
                   "cut at {cut}");
    }
}

#[test]
fn trailing_bytes_after_the_message_are_refused() {
    // A decoder that stopped at the end of the structure would let an
    // attacker append anything and still get the same verdict.
    let mut der = unhex(SIG_NOATTR);
    der.push(0);
    assert_eq!(parse::message(&der).err(), Some(Pkcs7Error::BadMessage));
}
