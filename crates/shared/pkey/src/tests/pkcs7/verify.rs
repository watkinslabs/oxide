// The signature itself: the known answers, and every tamper the check exists
// to catch.

use crate::pkcs7::{self, Pkcs7Error};

use super::fixtures::{ca_store, leaf_store, unhex, PAYLOAD, SIG_ATTR, SIG_CHAIN, SIG_NOATTR};

#[test]
fn a_real_signature_over_the_real_payload_verifies() {
    let (data, sig) = (unhex(PAYLOAD), unhex(SIG_NOATTR));
    assert_eq!(pkcs7::detached(&data, &sig, &leaf_store()), Ok(()));
}

#[test]
fn a_signature_with_signed_attributes_verifies() {
    // A different thing is signed here — the attribute set, not the content —
    // and the content is bound to it only through the messageDigest
    // attribute.
    let (data, sig) = (unhex(PAYLOAD), unhex(SIG_ATTR));
    assert_eq!(pkcs7::detached(&data, &sig, &leaf_store()), Ok(()));
}

#[test]
fn a_signature_carrying_its_whole_chain_verifies() {
    let (data, sig) = (unhex(PAYLOAD), unhex(SIG_CHAIN));
    assert_eq!(pkcs7::detached(&data, &sig, &leaf_store()), Ok(()));
}

#[test]
fn one_flipped_byte_of_data_is_rejected() {
    // The control for the whole feature. Without the digest step this passes.
    let (mut data, sig) = (unhex(PAYLOAD), unhex(SIG_NOATTR));
    let last = data.len() - 1;
    data[last] ^= 0x01;
    assert_eq!(pkcs7::detached(&data, &sig, &leaf_store()), Err(Pkcs7Error::KeyRejected));
}

#[test]
fn a_flipped_byte_of_data_is_rejected_under_signed_attributes_too() {
    // Here the rejection has to come from the messageDigest comparison, not
    // from the signature: the signature is over the attributes, which did not
    // change. A verifier that skipped that comparison would accept this.
    let (mut data, sig) = (unhex(PAYLOAD), unhex(SIG_ATTR));
    data[0] ^= 0x80;
    assert_eq!(pkcs7::detached(&data, &sig, &leaf_store()), Err(Pkcs7Error::KeyRejected));
}

#[test]
fn a_flipped_byte_of_signature_is_rejected() {
    let (data, mut sig) = (unhex(PAYLOAD), unhex(SIG_NOATTR));
    let last = sig.len() - 1;
    sig[last] ^= 0x01;
    assert_eq!(pkcs7::detached(&data, &sig, &leaf_store()), Err(Pkcs7Error::KeyRejected));
}

#[test]
fn a_signature_over_different_data_does_not_transfer() {
    // The same signature replayed onto other content: the exact attack a
    // detached signature invites.
    let sig = unhex(SIG_NOATTR);
    let other = alloc::vec![0x41u8; unhex(PAYLOAD).len()];
    assert_eq!(pkcs7::detached(&other, &sig, &leaf_store()), Err(Pkcs7Error::KeyRejected));
    // Including the empty message, which a length-blind digest would accept.
    assert_eq!(pkcs7::detached(&[], &sig, &leaf_store()), Err(Pkcs7Error::KeyRejected));
}

#[test]
fn a_shortened_or_lengthened_payload_is_rejected() {
    let (data, sig) = (unhex(PAYLOAD), unhex(SIG_NOATTR));
    assert_eq!(pkcs7::detached(&data[..data.len() - 1], &sig, &leaf_store()),
               Err(Pkcs7Error::KeyRejected));
    let mut longer = data.clone();
    longer.push(0);
    assert_eq!(pkcs7::detached(&longer, &sig, &leaf_store()), Err(Pkcs7Error::KeyRejected));
}

#[test]
fn a_message_carrying_its_own_content_is_refused() {
    // The signature must attest to the bytes the CALLER supplied. A message
    // that brings its own copy would otherwise verify against that copy and
    // say nothing about the caller's — the same signature would then pass for
    // any data at all.
    let sig = unhex(super::fixtures::SIG_ATTACHED);
    let data = unhex(PAYLOAD);
    assert_eq!(pkcs7::detached(&data, &sig, &leaf_store()), Err(Pkcs7Error::BadMessage));
    // Including against the very bytes it carries, which is the case a
    // verifier is most likely to let through.
    assert_eq!(pkcs7::detached(&[], &sig, &leaf_store()), Err(Pkcs7Error::BadMessage));
}

#[test]
fn a_signature_over_a_different_encapsulated_type_is_refused() {
    // The type is part of what was signed. A signature over some other
    // statement is a valid signature over the wrong thing.
    let mut sig = unhex(SIG_NOATTR);
    // The encapsulated type identifier, distinct from the outer signedData
    // one by its last octet.
    const DATA_OID: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
    let at = sig.windows(DATA_OID.len()).position(|w| w == DATA_OID)
        .expect("the message declares pkcs7-data");
    sig[at + DATA_OID.len() - 1] = 0x03;
    let data = unhex(PAYLOAD);
    assert_eq!(pkcs7::detached(&data, &sig, &leaf_store()), Err(Pkcs7Error::KeyRejected));
}

#[test]
fn a_malformed_signature_is_not_reported_as_a_bad_key() {
    // The distinction a caller acts on: a broken file is not an attack.
    let data = unhex(PAYLOAD);
    assert_eq!(pkcs7::detached(&data, b"", &leaf_store()), Err(Pkcs7Error::BadMessage));
    assert_eq!(pkcs7::detached(&data, b"\x30\x03\x02\x01\x01", &leaf_store()),
               Err(Pkcs7Error::BadMessage));
}

#[test]
fn an_empty_store_reaches_no_key_even_for_a_perfect_signature() {
    let (data, sig) = (unhex(PAYLOAD), unhex(SIG_NOATTR));
    let empty = pkcs7::TrustStore::new();
    assert!(empty.is_empty());
    assert_eq!(pkcs7::detached(&data, &sig, &empty), Err(Pkcs7Error::NoKey));
}

#[test]
fn the_store_reports_what_it_holds() {
    let s = ca_store();
    assert_eq!(s.len(), 1);
    assert!(!s.is_empty());
    let mut bad = pkcs7::TrustStore::new();
    assert_eq!(bad.add(b"not a certificate"), Err(Pkcs7Error::BadMessage));
    assert!(bad.is_empty());
}
