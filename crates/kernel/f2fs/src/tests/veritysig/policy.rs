//! What the policy accepts, what it refuses, and which answer each refusal
//! gets. Every case here is about the decision alone.

use super::fixtures::{unhex, CA_DER, LEAF_DER, OTHER_CA_DER, OTHER_SIG, SEALED_DIGEST,
                      SEALED_SIG};
use crate::verity::signature::{self, Policy, F_ALGORITHM, F_DIGEST, F_SIZE, MAGIC};
use crate::verity::uapi::{HASH_ALG_SHA256, HASH_ALG_SHA512};
use crate::verity::VerityError;
use syscall::errno::Errno;

fn digest() -> alloc::vec::Vec<u8> { unhex(SEALED_DIGEST) }

fn trusting(der: &str) -> Policy {
    let mut p = Policy::new();
    p.trust(&unhex(der)).expect("the certificate parses");
    p
}

#[test]
fn the_signed_blob_is_the_magic_the_algorithm_the_width_and_the_digest() {
    // Stated as bytes: this is what a signer outside this build signs, so a
    // layout that agreed only with itself would verify nothing anyone signed.
    let d = digest();
    let b = signature::formatted(HASH_ALG_SHA256, &d);
    assert_eq!(&b[..8], MAGIC);
    assert_eq!(&b[F_ALGORITHM..F_ALGORITHM + 2], &1u16.to_le_bytes());
    assert_eq!(&b[F_SIZE..F_SIZE + 2], &32u16.to_le_bytes());
    assert_eq!(&b[F_DIGEST..], &d[..]);
    assert_eq!(b.len(), 12 + 32);
}

#[test]
fn the_width_and_the_algorithm_are_part_of_what_is_signed() {
    // Otherwise a signature over a SHA-256 measurement could be presented as
    // the first 32 bytes of a SHA-512 one.
    let d = digest();
    assert_ne!(signature::formatted(HASH_ALG_SHA256, &d),
               signature::formatted(HASH_ALG_SHA512, &d));
    let mut wide = d.clone();
    wide.resize(64, 0);
    assert_ne!(&signature::formatted(HASH_ALG_SHA512, &wide)[..F_DIGEST],
               &signature::formatted(HASH_ALG_SHA512, &d)[..F_DIGEST]);
}

#[test]
fn an_unsigned_file_is_accepted_unless_signatures_are_required() {
    let mut p = Policy::new();
    assert_eq!(signature::verify(&p, HASH_ALG_SHA256, &digest(), &[]), Ok(()));
    p.require = true;
    assert_eq!(signature::verify(&p, HASH_ALG_SHA256, &digest(), &[]),
               Err(VerityError::SignatureRequired));
    assert_eq!(VerityError::SignatureRequired.errno(), Errno::Eperm);
}

#[test]
fn a_signed_file_is_checked_even_when_signatures_are_not_required() {
    // The policy decides whether an ABSENT signature is tolerated, never
    // whether a present one is examined. A build that skipped the check when
    // `require` was false would accept the replay below.
    let p = trusting(LEAF_DER);
    assert!(!p.require);
    assert_eq!(signature::verify(&p, HASH_ALG_SHA256, &digest(), &unhex(SEALED_SIG)), Ok(()));
    assert_eq!(signature::verify(&p, HASH_ALG_SHA256, &digest(), &unhex(OTHER_SIG)),
               Err(VerityError::BadSignature));
}

#[test]
fn a_signed_file_and_an_empty_keyring_is_refused_rather_than_waved_through() {
    // And without parsing the signature at all: an unparsed blob is one less
    // thing reachable by anyone who can turn verity on.
    let p = Policy::new();
    assert!(p.store.is_empty());
    assert_eq!(signature::verify(&p, HASH_ALG_SHA256, &digest(), &unhex(SEALED_SIG)),
               Err(VerityError::NoKey));
    // Even a blob that is not a signature at all gets the same answer.
    assert_eq!(signature::verify(&p, HASH_ALG_SHA256, &digest(), b"rubbish"),
               Err(VerityError::NoKey));
    assert_eq!(VerityError::NoKey.errno(), Errno::Enokey);
}

#[test]
fn a_chain_reaching_only_an_untrusted_authority_is_refused() {
    let p = trusting(OTHER_CA_DER);
    assert_eq!(signature::verify(&p, HASH_ALG_SHA256, &digest(), &unhex(SEALED_SIG)),
               Err(VerityError::NoKey));
}

#[test]
fn the_authority_that_issued_the_signer_is_enough() {
    let p = trusting(CA_DER);
    assert_eq!(signature::verify(&p, HASH_ALG_SHA256, &digest(), &unhex(SEALED_SIG)), Ok(()));
}

#[test]
fn a_signature_over_another_files_measurement_is_rejected() {
    // The replay: a real signature by a trusted key over a different
    // measurement. Checking that the blob merely verifies — without binding
    // it to THIS file's digest — accepts this.
    let p = trusting(CA_DER);
    let mut other = digest();
    other[0] ^= 0xff;
    assert_eq!(signature::verify(&p, HASH_ALG_SHA256, &other, &unhex(SEALED_SIG)),
               Err(VerityError::BadSignature));
    assert_eq!(VerityError::BadSignature.errno(), Errno::Ekeyrejected);
}

#[test]
fn one_flipped_byte_of_signature_is_rejected() {
    let p = trusting(CA_DER);
    let mut sig = unhex(SEALED_SIG);
    let last = sig.len() - 1;
    sig[last] ^= 0x01;
    assert_eq!(signature::verify(&p, HASH_ALG_SHA256, &digest(), &sig),
               Err(VerityError::BadSignature));
}

#[test]
fn a_signature_that_is_not_one_is_reported_as_malformed_not_as_tampering() {
    // The distinction a caller acts on: a broken file is not an attack.
    let p = trusting(CA_DER);
    for blob in [&b"not der"[..], &[0x30, 0x03, 0x02, 0x01, 0x01][..]] {
        assert_eq!(signature::verify(&p, HASH_ALG_SHA256, &digest(), blob),
                   Err(VerityError::MalformedSignature));
    }
    // Truncating a real one is malformed too, never a rejected key.
    let sig = unhex(SEALED_SIG);
    assert_eq!(signature::verify(&p, HASH_ALG_SHA256, &digest(), &sig[..sig.len() / 2]),
               Err(VerityError::MalformedSignature));
    assert_eq!(VerityError::MalformedSignature.errno(), Errno::Ebadmsg);
}

#[test]
fn a_certificate_that_is_not_one_does_not_join_the_keyring() {
    let mut p = Policy::new();
    assert_eq!(p.trust(b"not a certificate"), Err(VerityError::MalformedSignature));
    assert!(p.store.is_empty());
}
