// PCR arithmetic and the bank inventory a driver validates against.
//
// The known-answer vectors below are the digests of the exact byte strings the
// extend chain must hash; a build that hashes anything else — the operands in
// the other order, or a differently sized operand — fails at least one.
//
// There is deliberately NO test here for register contents, reset values or
// resettability. The kernel holds no register contents: a PCR lives in the
// chip, `extend_value` only predicts what one will hold so a log can be
// replayed, and reset semantics are chip-internal behaviour the reference
// never models. Tests for those things previously existed and passed against a
// simulator that no measurement ever left.

use alloc::vec;

use super::support::hex;
use crate::alg::Alg;
use crate::limits::PLATFORM_PCR;
use crate::pcr::{extend_value, AllocatedBanks, PcrError};

/// SHA-256 of 64 zero bytes: a zeroed SHA-256 register extended once with an
/// all-zero measurement.
const SHA256_EXTEND_ZERO_ONCE: &str = "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b";
/// The same register extended a second time with an all-zero measurement.
const SHA256_EXTEND_ZERO_TWICE: &str = "7a0501f5957bdf9cb3a8ff4966f02265f968658b7a9c62642cba1165e86642f5";
/// SHA-256 of 32 zero bytes followed by 32 all-ones bytes.
const SHA256_ZERO_THEN_ONES: &str = "bba91ca85dc914b2ec3efb9e16e7267bf9193b14350d20fba8a8b406730ae30a";
/// SHA-256 of the same two operands in the OTHER order.
const SHA256_ONES_THEN_ZERO: &str = "a5de9b714accd8afaaabf1cbd6e1014c9d07ff95c2ae154d91ec68485b31e7b5";
/// SHA-1 of 40 zero bytes.
const SHA1_EXTEND_ZERO_ONCE: &str = "b80de5d138758541c5f05265ad144ab9fa86d1db";
/// SHA-384 of 96 zero bytes.
const SHA384_EXTEND_ZERO_ONCE: &str =
    "f57bb7ed82c6ae4a29e6c9879338c592c7d42a39135583e8ccbe3940f2344b0eb6eb8503db0ffd6a39ddd00cd07d8317";
/// SHA-512 of 128 zero bytes.
const SHA512_EXTEND_ZERO_ONCE: &str = "ab942f526272e456ed68a979f50202905ca903a141ed98443567b11ef0bf25a552d639051a01be58558122c58e3de07d749ee59ded36acf0c55cd91924d6ba11";

#[test]
fn extend_from_zero_matches_known_vector_sha256() {
    let v = extend_value(Alg::Sha256, &[0u8; 32], &[0u8; 32]).unwrap();
    assert_eq!(v, hex(SHA256_EXTEND_ZERO_ONCE));
}

#[test]
fn extend_chains_matches_known_vector_sha256() {
    let once = extend_value(Alg::Sha256, &[0u8; 32], &[0u8; 32]).unwrap();
    let twice = extend_value(Alg::Sha256, &once, &[0u8; 32]).unwrap();
    assert_eq!(twice, hex(SHA256_EXTEND_ZERO_TWICE));
}

#[test]
fn extend_hashes_old_then_measurement_not_the_reverse() {
    // The one asymmetric vector. Every all-zero vector above is symmetric in
    // its operands and cannot catch a swap; this is the test that pins the
    // order, and with it the forgery argument.
    let v = extend_value(Alg::Sha256, &[0x00u8; 32], &[0xffu8; 32]).unwrap();
    assert_eq!(v, hex(SHA256_ZERO_THEN_ONES));
    assert_ne!(v, hex(SHA256_ONES_THEN_ZERO));
}

#[test]
fn extend_from_zero_matches_known_vector_sha1() {
    let v = extend_value(Alg::Sha1, &[0u8; 20], &[0u8; 20]).unwrap();
    assert_eq!(v, hex(SHA1_EXTEND_ZERO_ONCE));
}

#[test]
fn extend_from_zero_matches_known_vector_sha384_and_sha512() {
    let v384 = extend_value(Alg::Sha384, &[0u8; 48], &[0u8; 48]).unwrap();
    assert_eq!(v384, hex(SHA384_EXTEND_ZERO_ONCE));
    let v512 = extend_value(Alg::Sha512, &[0u8; 64], &[0u8; 64]).unwrap();
    assert_eq!(v512, hex(SHA512_EXTEND_ZERO_ONCE));
}

#[test]
fn extend_refuses_a_measurement_of_the_wrong_width() {
    assert_eq!(extend_value(Alg::Sha256, &[0u8; 32], &[0u8; 20]),
               Err(PcrError::BadDigestLen { expected: 32, got: 20 }));
    assert_eq!(extend_value(Alg::Sha256, &[0u8; 20], &[0u8; 32]),
               Err(PcrError::BadDigestLen { expected: 32, got: 20 }));
}

#[test]
fn an_unsupported_algorithm_is_refused_rather_than_substituted() {
    // A bank whose hash this kernel cannot compute must fail, not quietly
    // produce a digest under some other algorithm.
    assert_eq!(extend_value(Alg::Sm3, &[0u8; 32], &[0u8; 32]),
               Err(PcrError::UnsupportedAlg(Alg::Sm3.id())));
}

#[test]
fn an_extend_must_carry_a_digest_for_every_allocated_bank() {
    let banks = AllocatedBanks::new(&[Alg::Sha1, Alg::Sha256]).unwrap();
    let sha256 = [0u8; 32];
    // SHA-1 allocated but absent from the request: the chip would extend it
    // anyway, so a partial request is refused rather than sent.
    assert_eq!(banks.check_extend(10, &[(Alg::Sha256.id(), &sha256[..])]),
               Err(PcrError::MissingBank(Alg::Sha1.id())));
}

#[test]
fn an_extend_naming_an_unallocated_bank_is_refused() {
    let banks = AllocatedBanks::new(&[Alg::Sha256]).unwrap();
    let sha256 = [0u8; 32];
    let sha384 = [0u8; 48];
    assert_eq!(banks.check_extend(10, &[(Alg::Sha256.id(), &sha256[..]),
                                        (Alg::Sha384.id(), &sha384[..])]),
               Err(PcrError::UnknownBank(Alg::Sha384.id())));
}

#[test]
fn an_extend_with_a_digest_sized_for_another_bank_is_refused() {
    let banks = AllocatedBanks::new(&[Alg::Sha256]).unwrap();
    let wrong = [0u8; 20];
    assert_eq!(banks.check_extend(10, &[(Alg::Sha256.id(), &wrong[..])]),
               Err(PcrError::BadDigestLen { expected: 32, got: 20 }));
}

#[test]
fn an_extend_outside_the_platform_range_is_refused() {
    let banks = AllocatedBanks::new(&[Alg::Sha256]).unwrap();
    let d = [0u8; 32];
    assert_eq!(banks.check_extend(PLATFORM_PCR, &[(Alg::Sha256.id(), &d[..])]),
               Err(PcrError::BadIndex(PLATFORM_PCR)));
}

#[test]
fn a_well_formed_agile_extend_is_admitted() {
    let banks = AllocatedBanks::new(&[Alg::Sha1, Alg::Sha256]).unwrap();
    let sha1 = [0u8; 20];
    let sha256 = [0u8; 32];
    assert_eq!(banks.check_extend(10, &[(Alg::Sha1.id(), &sha1[..]),
                                        (Alg::Sha256.id(), &sha256[..])]), Ok(()));
}

#[test]
fn bank_sets_are_bounded_and_unique() {
    assert_eq!(AllocatedBanks::new(&[]).err(), Some(PcrError::BadBankSet));
    assert_eq!(AllocatedBanks::new(&[Alg::Sha256, Alg::Sha256]).err(), Some(PcrError::BadBankSet));
    let b = AllocatedBanks::new(&[Alg::Sha256, Alg::Sha1]).unwrap();
    assert_eq!(b.len(), 2);
    assert_eq!(b.algs(), vec![Alg::Sha256, Alg::Sha1]);
    assert_eq!(b.bank(Alg::Sha256).unwrap().digest_size(), 32);
    assert_eq!(b.bank(Alg::Sha384).err(), Some(PcrError::UnknownBank(Alg::Sha384.id())));
}

#[test]
fn the_inventory_records_width_and_never_a_value() {
    // The bank record is metadata. If a future change gives it storage, this
    // is the test that should have to be deleted first.
    let b = AllocatedBanks::new(&[Alg::Sha256]).unwrap();
    let info = b.bank(Alg::Sha256).unwrap();
    assert_eq!(info.alg_id(), Alg::Sha256.id());
    assert_eq!(info.digest_size(), 32);
    assert_eq!(core::mem::size_of_val(info), core::mem::size_of::<Alg>());
}
