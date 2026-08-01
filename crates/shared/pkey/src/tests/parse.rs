// Certificate and private-key parsing, and the name a blob proposes for
// itself.

use super::fixtures::*;
use crate::key::{AsymmetricKey, ID_TYPE_PKCS8, ID_TYPE_X509};
use crate::{x509, PkeyError};

#[test]
fn certificate_yields_a_public_key_and_its_name() {
    let cert = x509::parse(&unhex(CERT_DER)).expect("a well-formed certificate");
    assert_eq!(cert.algo, "rsa");
    assert_eq!(cert.subject, "Oxide Test: pkey vector",
        "an organization the common name does not already carry is joined to it");
    assert_eq!(hexed(&cert.skid.expect("the certificate carries one")), SKID_HEX);
    assert_eq!(hexed(&cert.serial), "280d0bb06dc810c24687dae3d19387bd2fdea38f");

    let key = AsymmetricKey::parse(&unhex(CERT_DER)).expect("parses");
    assert_eq!(key.id_type, ID_TYPE_X509);
    assert!(!key.is_private(), "a certificate carries only the public half");
    // The proposed description is the subject followed by the key identifier,
    // which is what names the key when the caller supplies no description.
    assert_eq!(key.description.as_deref(), Some(&*alloc::format!("Oxide Test: pkey vector: {SKID_HEX}")));
}

#[test]
fn pkcs8_yields_a_private_key_with_no_name() {
    let key = AsymmetricKey::parse(&unhex(KEY_PKCS8)).expect("parses");
    assert_eq!(key.id_type, ID_TYPE_PKCS8);
    assert_eq!(key.algo, "rsa");
    assert!(key.is_private());
    assert_eq!(key.description, None,
        "a private-key blob proposes no name, so its caller must supply one");
}

// A blob that is neither format, and a truncated one, are not keys.
#[test]
fn rubbish_is_not_a_key() {
    assert_eq!(AsymmetricKey::parse(b"not a key at all").err(), Some(PkeyError::BadMessage));
    let der = unhex(CERT_DER);
    assert!(AsymmetricKey::parse(&der[..der.len() - 1]).is_err(), "a truncated certificate");
    assert!(AsymmetricKey::parse(&[]).is_err());
}

// The two halves of the same key must agree on the modulus, or a signature
// made with one would not verify with the other.
#[test]
fn the_two_blobs_describe_one_key() {
    let pubk = AsymmetricKey::parse(&unhex(CERT_DER)).expect("parses");
    let privk = AsymmetricKey::parse(&unhex(KEY_PKCS8)).expect("parses");
    let q1 = pubk.query("raw", None).expect("raw is always available");
    let q2 = privk.query("raw", None).expect("raw is always available");
    assert_eq!(q1.key_size, 1024);
    assert_eq!(q1.key_size, q2.key_size);
    assert_eq!(q1.max_enc_size, q2.max_enc_size);
}

// Key sizes outside the accepted set are refused when the key is built, so an
// odd-sized key never reaches the arithmetic.
#[test]
fn unusual_modulus_sizes_are_refused() {
    use crate::rsa::RsaKey;
    let e = [0x01, 0x00, 0x01];
    assert!(RsaKey::new(&alloc::vec![0xffu8; 128], &e, None).is_ok(), "1024 bits");
    assert_eq!(RsaKey::new(&alloc::vec![0xffu8; 100], &e, None).err(), Some(PkeyError::BadKey));
    assert_eq!(RsaKey::new(&alloc::vec![0xffu8; 1024], &e, None).err(), Some(PkeyError::BadKey));
    assert_eq!(RsaKey::new(&[], &e, None).err(), Some(PkeyError::BadKey), "a zero modulus");
    assert_eq!(RsaKey::new(&alloc::vec![0xffu8; 128], &[], None).err(), Some(PkeyError::BadKey),
        "a zero exponent");
}
