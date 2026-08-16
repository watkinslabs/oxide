// Which chains reach a store and which do not. Every case here is about
// trust alone: the signature is the same valid signature throughout.

use crate::pkcs7::{self, Pkcs7Error};

use super::fixtures::{ca_store, leaf_store, unhex, CA_DER, LEAF_DER, PAYLOAD, SIG_CHAIN,
                      SIG_NOATTR};

#[test]
fn the_authority_alone_is_enough_when_the_message_carries_the_chain() {
    // The store holds only the issuer. Trust is reached by climbing from the
    // signing certificate to it, and the issuer's key is then required to
    // have signed the certificate below.
    let (data, sig) = (unhex(PAYLOAD), unhex(SIG_CHAIN));
    assert_eq!(pkcs7::detached(&data, &sig, &ca_store()), Ok(()));
}

#[test]
fn the_authority_is_reached_even_when_the_message_omits_it() {
    // The message carries only the signing certificate; the authority is
    // named by its extension and not shipped. The chain runs out inside the
    // message, and the certificate it ran out at names an authority the
    // store holds — so the trusted copy is asked to verify the certificate
    // below it, and does. Requiring the authority to be shipped as well
    // would reject exactly the shortest valid chains.
    let (data, sig) = (unhex(PAYLOAD), unhex(SIG_NOATTR));
    assert_eq!(pkcs7::detached(&data, &sig, &ca_store()), Ok(()));
}

#[test]
fn a_named_authority_that_did_not_sign_the_certificate_is_rejected() {
    // Same shape as above, and the store's copy of the named authority is an
    // impostor. The name leads to it and its key did not produce the
    // signature on the certificate below, which is the check that matters.
    let mut store = pkcs7::TrustStore::new();
    store.add(&unhex(super::fixtures::IMPOSTOR_CA_DER)).expect("parses");
    let (data, sig) = (unhex(PAYLOAD), unhex(SIG_NOATTR));
    assert_eq!(pkcs7::detached(&data, &sig, &store), Err(Pkcs7Error::KeyRejected));
}

#[test]
fn a_store_holding_the_signer_itself_is_enough() {
    let (data, sig) = (unhex(PAYLOAD), unhex(SIG_NOATTR));
    assert_eq!(pkcs7::detached(&data, &sig, &leaf_store()), Ok(()));
}

#[test]
fn a_store_holding_an_unrelated_certificate_reaches_no_key() {
    // A certificate that is trusted but has nothing to do with this chain
    // must not make the chain trusted.
    let mut store = pkcs7::TrustStore::new();
    store.add(&unhex(super::fixtures::OTHER_CA_DER)).expect("parses");
    let (data, sig) = (unhex(PAYLOAD), unhex(SIG_CHAIN));
    assert_eq!(pkcs7::detached(&data, &sig, &store), Err(Pkcs7Error::NoKey));
}

#[test]
fn a_store_holding_an_impostor_with_the_right_name_is_rejected() {
    // The impostor certificate was minted with the SAME subject, issuer and
    // serial number as the real authority, so it matches by identity — and
    // its key did not sign anything in this chain. Identity is the claim
    // being tested, never the test itself; a verifier that stopped at the
    // name match would accept this.
    let mut store = pkcs7::TrustStore::new();
    store.add(&unhex(super::fixtures::IMPOSTOR_CA_DER)).expect("parses");
    let (data, sig) = (unhex(PAYLOAD), unhex(SIG_CHAIN));
    assert_eq!(pkcs7::detached(&data, &sig, &store), Err(Pkcs7Error::KeyRejected));
}

#[test]
fn both_certificates_trusted_still_verifies() {
    let mut store = pkcs7::TrustStore::new();
    store.add(&unhex(LEAF_DER)).unwrap();
    store.add(&unhex(CA_DER)).unwrap();
    let (data, sig) = (unhex(PAYLOAD), unhex(SIG_CHAIN));
    assert_eq!(pkcs7::detached(&data, &sig, &store), Ok(()));
}
