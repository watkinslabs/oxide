// Query, encrypt/decrypt and sign/verify: known answers, round trips, and the
// error each malformed request produces.

use super::fixtures::*;
use crate::key::{AsymmetricKey, Operation};
use crate::PkeyError;

fn public() -> AsymmetricKey { AsymmetricKey::parse(&unhex(CERT_DER)).expect("parses") }
fn private() -> AsymmetricKey { AsymmetricKey::parse(&unhex(KEY_PKCS8)).expect("parses") }

/// Deterministic non-zero padding, so an encryption test has a fixed answer.
fn fixed_rand(buf: &mut [u8]) { for (i, b) in buf.iter_mut().enumerate() { *b = (i as u8) | 0x41; } }

// What `raw` and `pkcs1` each report, and how the private half changes it.
#[test]
fn query_reports_the_operations_the_encoding_allows() {
    let pubq = public().query("raw", None).expect("raw is always available");
    assert_eq!(pubq.key_size, 1024, "the key size is reported in BITS");
    assert_eq!((pubq.max_data_size, pubq.max_sig_size, pubq.max_enc_size, pubq.max_dec_size),
        (128, 128, 128, 128), "every width is the modulus in bytes");
    assert_eq!((pubq.can_encrypt, pubq.can_decrypt, pubq.can_sign, pubq.can_verify),
        (true, false, false, false), "an unpadded primitive cannot express a signature");

    let privq = private().query("raw", None).expect("raw is always available");
    assert_eq!((privq.can_encrypt, privq.can_decrypt, privq.can_sign, privq.can_verify),
        (true, true, false, false), "the private half adds decryption");

    let pubq = public().query("pkcs1", None).expect("pkcs1 is always available");
    assert_eq!((pubq.can_encrypt, pubq.can_decrypt, pubq.can_sign, pubq.can_verify),
        (true, false, false, true), "a public key verifies but cannot sign");
    let privq = private().query("pkcs1", Some("sha256")).expect("a named digest");
    assert_eq!((privq.can_encrypt, privq.can_decrypt, privq.can_sign, privq.can_verify),
        (true, true, true, true));
}

// The encoding name is not free-form, and a digest name means nothing to an
// unpadded primitive.
#[test]
fn query_rejects_encodings_it_cannot_honour() {
    assert_eq!(public().query("oaep", None), Err(PkeyError::Invalid));
    assert_eq!(public().query("", None), Err(PkeyError::Invalid));
    assert_eq!(public().query("raw", Some("sha256")), Err(PkeyError::Invalid),
        "unpadded RSA cannot distinguish one digest from another");
    assert_eq!(public().query("pkcs1", Some("sha3-224")), Err(PkeyError::NoAlgorithm),
        "a digest with no encoding prefix is absent, not invalid");
}

// The published signature over a known digest, and the verification of it.
#[test]
fn known_answer_signature() {
    let digest = unhex(DIGEST_SHA256);
    let sig = private().eds(Operation::Sign, "pkcs1", Some("sha256"), &digest, fixed_rand)
        .expect("signs");
    assert_eq!(hexed(&sig), SIG_SHA256, "PKCS#1 v1.5 signing is deterministic");
    assert_eq!(sig.len(), 128);
    public().verify("pkcs1", Some("sha256"), &digest, &sig).expect("verifies under the public half");
}

// A signature that is well formed but wrong is a REJECTED key; a block that is
// not a v1.5 signature at all is malformed. A caller that cannot tell them
// apart cannot tell an attack from a bug.
#[test]
fn verification_failures_are_distinguishable() {
    let digest = unhex(DIGEST_SHA256);
    let sig = unhex(SIG_SHA256);
    let mut other = digest.clone();
    other[0] ^= 1;
    assert_eq!(public().verify("pkcs1", Some("sha256"), &other, &sig), Err(PkeyError::Rejected));

    let mut mangled = sig.clone();
    mangled[64] ^= 0xff;
    assert_eq!(public().verify("pkcs1", Some("sha256"), &digest, &mangled), Err(PkeyError::BadMessage));

    // The digest length must be the one the named algorithm produces.
    assert_eq!(public().verify("pkcs1", Some("sha256"), &digest[..16], &sig), Err(PkeyError::Invalid));
    // A signature must be exactly as wide as the modulus.
    assert_eq!(public().verify("pkcs1", Some("sha256"), &digest, &sig[..127]), Err(PkeyError::Invalid));
    // Naming a different digest makes the prefix inside the block wrong.
    assert_eq!(public().verify("pkcs1", Some("sha512"), &digest, &sig), Err(PkeyError::Invalid),
        "a sha512 signature carries a 64-byte digest");
    let d512 = alloc::vec![0u8; 64];
    assert_eq!(public().verify("pkcs1", Some("sha512"), &d512, &sig), Err(PkeyError::BadMessage));
}

// Signing needs the private half; verification does not.
#[test]
fn signing_needs_the_private_half() {
    let digest = unhex(DIGEST_SHA256);
    assert_eq!(public().eds(Operation::Sign, "pkcs1", Some("sha256"), &digest, fixed_rand),
        Err(PkeyError::NoPrivateKey));
    // An unencoded RSA value cannot say "this is a signature", so signing
    // without an encoding is not a weaker signature — it is not one.
    assert_eq!(private().eds(Operation::Sign, "raw", None, &digest, fixed_rand),
        Err(PkeyError::Invalid));
    assert_eq!(public().verify("raw", None, &digest, &unhex(SIG_SHA256)),
        Err(PkeyError::NoAlgorithm), "there is no signature algorithm for a raw value");
}

// Encryption round-trips through the private half, and the padding makes the
// ciphertext depend on the entropy supplied.
#[test]
fn pkcs1_encryption_round_trip() {
    let msg = b"oxide pkey vector";
    let ct = public().eds(Operation::Encrypt, "pkcs1", None, msg, fixed_rand).expect("encrypts");
    assert_eq!(ct.len(), 128);
    let pt = private().eds(Operation::Decrypt, "pkcs1", None, &ct, fixed_rand).expect("decrypts");
    assert_eq!(pt, msg);

    let mut counter = 0u8;
    let other = public().eds(Operation::Encrypt, "pkcs1", None, msg,
        |b: &mut [u8]| { for x in b.iter_mut() { counter = counter.wrapping_add(7); *x = counter | 1; } })
        .expect("encrypts");
    assert_ne!(other, ct, "different padding must give a different ciphertext");
    assert_eq!(private().eds(Operation::Decrypt, "pkcs1", None, &other, fixed_rand).expect("decrypts"),
        msg);
}

// The padded encoding leaves room for eleven octets of overhead, and refuses a
// message that does not fit rather than truncating it.
#[test]
fn pkcs1_encryption_length_rules() {
    let ok = alloc::vec![0x5au8; 117];
    assert!(public().eds(Operation::Encrypt, "pkcs1", None, &ok, fixed_rand).is_ok());
    let too_long = alloc::vec![0x5au8; 118];
    assert_eq!(public().eds(Operation::Encrypt, "pkcs1", None, &too_long, fixed_rand),
        Err(PkeyError::Overflow));
    // A ciphertext that is not modulus-wide never decrypts.
    assert_eq!(private().eds(Operation::Decrypt, "pkcs1", None, &alloc::vec![0u8; 127], fixed_rand),
        Err(PkeyError::Invalid));
    // Decryption needs the private half.
    let ct = public().eds(Operation::Encrypt, "pkcs1", None, b"x", fixed_rand).expect("encrypts");
    assert_eq!(public().eds(Operation::Decrypt, "pkcs1", None, &ct, fixed_rand),
        Err(PkeyError::NoPrivateKey));
    // A block whose padding is not a v1.5 encryption block is refused.
    let junk = private().eds(Operation::Encrypt, "raw", None, &alloc::vec![0x11u8; 64], fixed_rand)
        .expect("raw encrypts");
    assert_eq!(private().eds(Operation::Decrypt, "pkcs1", None, &junk, fixed_rand),
        Err(PkeyError::Invalid));
}

// The unpadded primitive round-trips too, and refuses an input the modulus
// cannot represent.
#[test]
fn raw_primitive_round_trip() {
    let m = alloc::vec![0x11u8; 64];
    let c = public().eds(Operation::Encrypt, "raw", None, &m, fixed_rand).expect("encrypts");
    assert_eq!(c.len(), 128);
    let back = private().eds(Operation::Decrypt, "raw", None, &c, fixed_rand).expect("decrypts");
    assert_eq!(&back[128 - m.len()..], &m[..], "the value comes back zero-padded to the modulus");
    let too_big = alloc::vec![0xffu8; 128];
    assert_eq!(public().eds(Operation::Encrypt, "raw", None, &too_big, fixed_rand),
        Err(PkeyError::Invalid), "an input at least as large as the modulus has no representative");
}

// The empty prefix signs whatever length the caller hands over, which is what
// the protocols that predate DigestInfo need.
#[test]
fn the_empty_prefix_signs_a_bare_value() {
    let bare = alloc::vec![0x42u8; 20];
    let sig = private().eds(Operation::Sign, "pkcs1", None, &bare, fixed_rand).expect("signs");
    public().verify("pkcs1", None, &bare, &sig).expect("verifies");
    public().verify("pkcs1", Some("none"), &bare, &sig).expect("`none` names the same prefix");
    assert_eq!(public().verify("pkcs1", Some("sha256"), &bare, &sig), Err(PkeyError::Invalid),
        "a 20-byte value is not a sha256 digest");
}
