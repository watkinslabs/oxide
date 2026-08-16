// PCR arithmetic. The known-answer vectors below are the digests of the
// exact byte strings the extend operation must hash; a build that hashes
// anything else — the operands in the other order, a differently sized
// operand, or only the first bank — fails at least one of them.

use alloc::vec;
use alloc::vec::Vec;

use super::support::hex;
use crate::alg::Alg;
use crate::limits::PLATFORM_PCR;
use crate::pcr::{
    extend_value, is_resettable, reset_fill, Bank, Banks, PcrError, ResetCause, APPLICATION_PCR,
    DEBUG_PCR, DRTM_LOCALITY, DRTM_PCR_FIRST, DRTM_PCR_LAST,
};

/// SHA-256 of 64 zero bytes: a reset SHA-256 register extended once with an
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
fn extend_from_reset_matches_known_vector_sha256() {
    let mut b = Bank::new(Alg::Sha256);
    b.extend(0, &[0u8; 32]).unwrap();
    assert_eq!(b.read(0).unwrap(), hex(SHA256_EXTEND_ZERO_ONCE).as_slice());
}

#[test]
fn extend_chains_matches_known_vector_sha256() {
    let mut b = Bank::new(Alg::Sha256);
    b.extend(0, &[0u8; 32]).unwrap();
    b.extend(0, &[0u8; 32]).unwrap();
    assert_eq!(b.read(0).unwrap(), hex(SHA256_EXTEND_ZERO_TWICE).as_slice());
}

#[test]
fn extend_hashes_old_then_measurement_not_the_reverse() {
    // The two orders are both 32-byte SHA-256 digests; only one is the PCR
    // contract, and swapping them is what makes a log forgeable.
    let old = [0u8; 32];
    let m = [0xffu8; 32];
    let got = extend_value(Alg::Sha256, &old, &m).unwrap();
    assert_eq!(got, hex(SHA256_ZERO_THEN_ONES));
    assert_ne!(got, hex(SHA256_ONES_THEN_ZERO));
}

#[test]
fn extend_from_reset_matches_known_vector_sha1() {
    let mut b = Bank::new(Alg::Sha1);
    b.extend(0, &[0u8; 20]).unwrap();
    assert_eq!(b.read(0).unwrap(), hex(SHA1_EXTEND_ZERO_ONCE).as_slice());
}

#[test]
fn extend_from_reset_matches_known_vector_sha384_and_sha512() {
    let mut b = Bank::new(Alg::Sha384);
    b.extend(0, &[0u8; 48]).unwrap();
    assert_eq!(b.read(0).unwrap(), hex(SHA384_EXTEND_ZERO_ONCE).as_slice());
    let mut b = Bank::new(Alg::Sha512);
    b.extend(0, &[0u8; 64]).unwrap();
    assert_eq!(b.read(0).unwrap(), hex(SHA512_EXTEND_ZERO_ONCE).as_slice());
}

#[test]
fn extend_refuses_a_measurement_of_the_wrong_width() {
    let mut b = Bank::new(Alg::Sha256);
    assert_eq!(b.extend(0, &[0u8; 20]), Err(PcrError::BadDigestLen { expected: 32, got: 20 }));
    assert_eq!(b.extend(0, &[0u8; 64]), Err(PcrError::BadDigestLen { expected: 32, got: 64 }));
    assert_eq!(b.extend(0, &[]), Err(PcrError::BadDigestLen { expected: 32, got: 0 }));
    // A refused extend leaves the register at its reset value.
    assert_eq!(b.read(0).unwrap(), [0u8; 32]);
}

#[test]
fn extend_touches_only_the_named_register() {
    let mut b = Bank::new(Alg::Sha256);
    b.extend(10, &[0u8; 32]).unwrap();
    assert_eq!(b.read(10).unwrap(), hex(SHA256_EXTEND_ZERO_ONCE).as_slice());
    for i in 0..PLATFORM_PCR {
        if i == 10 { continue; }
        assert_eq!(b.read(i).unwrap(), &vec![reset_fill(i); 32][..], "register {i} moved");
    }
}

#[test]
fn extend_rejects_an_index_outside_the_platform_range() {
    let mut b = Bank::new(Alg::Sha256);
    assert_eq!(b.extend(PLATFORM_PCR, &[0u8; 32]), Err(PcrError::BadIndex(PLATFORM_PCR)));
    assert_eq!(b.read(PLATFORM_PCR + 5), Err(PcrError::BadIndex(PLATFORM_PCR + 5)));
}

#[test]
fn reset_values_distinguish_dynamic_registers() {
    let b = Bank::new(Alg::Sha256);
    for i in 0..PLATFORM_PCR {
        let want = if (DRTM_PCR_FIRST..=DRTM_PCR_LAST).contains(&i) { 0xff } else { 0x00 };
        assert_eq!(reset_fill(i), want, "fill for register {i}");
        assert!(b.read(i).unwrap().iter().all(|x| *x == want), "register {i} reset value");
    }
}

#[test]
fn resettability_follows_the_platform_profile() {
    for i in 0..=15 {
        for loc in 0..=4 { assert!(!is_resettable(i, loc), "static register {i} must not be resettable"); }
    }
    for loc in 0..=4u8 {
        assert!(is_resettable(DEBUG_PCR, loc));
        assert!(is_resettable(APPLICATION_PCR, loc));
    }
    for i in DRTM_PCR_FIRST..=DRTM_PCR_LAST {
        for loc in 0..=3u8 { assert!(!is_resettable(i, loc), "dynamic register {i} from locality {loc}"); }
        assert!(is_resettable(i, DRTM_LOCALITY));
    }
    assert!(!is_resettable(PLATFORM_PCR, DRTM_LOCALITY));
}

#[test]
fn command_reset_is_refused_from_the_wrong_locality() {
    let mut b = Bank::new(Alg::Sha256);
    b.extend(DEBUG_PCR, &[1u8; 32]).unwrap();
    assert_eq!(b.reset(0, ResetCause::Command(0)), Err(PcrError::NotResettable { index: 0, locality: 0 }));
    assert_eq!(b.reset(DRTM_PCR_FIRST, ResetCause::Command(0)),
               Err(PcrError::NotResettable { index: DRTM_PCR_FIRST, locality: 0 }));
    b.reset(DEBUG_PCR, ResetCause::Command(0)).unwrap();
    assert_eq!(b.read(DEBUG_PCR).unwrap(), [0u8; 32]);
    b.reset(DRTM_PCR_FIRST, ResetCause::Command(DRTM_LOCALITY)).unwrap();
    assert_eq!(b.read(DRTM_PCR_FIRST).unwrap(), [0u8; 32]);
}

#[test]
fn measured_launch_zeroes_only_the_dynamic_registers() {
    let mut b = Bank::new(Alg::Sha256);
    b.extend(0, &[0u8; 32]).unwrap();
    let static_before = b.read(0).unwrap().to_vec();
    b.reset_all(ResetCause::DrtmStart);
    assert_eq!(b.read(0).unwrap(), static_before.as_slice());
    for i in DRTM_PCR_FIRST..=DRTM_PCR_LAST { assert_eq!(b.read(i).unwrap(), [0u8; 32]); }
}

#[test]
fn agile_extend_updates_every_allocated_bank() {
    let mut banks = Banks::new(&[Alg::Sha1, Alg::Sha256]).unwrap();
    let d1 = [0u8; 20];
    let d256 = [0u8; 32];
    banks.extend(7, &[(Alg::Sha1.id(), &d1[..]), (Alg::Sha256.id(), &d256[..])]).unwrap();
    assert_eq!(banks.read(Alg::Sha1, 7).unwrap(), hex(SHA1_EXTEND_ZERO_ONCE).as_slice());
    assert_eq!(banks.read(Alg::Sha256, 7).unwrap(), hex(SHA256_EXTEND_ZERO_ONCE).as_slice());
    // and only register 7 moved, in both banks
    assert_eq!(banks.read(Alg::Sha1, 6).unwrap(), [0u8; 20]);
    assert_eq!(banks.read(Alg::Sha256, 6).unwrap(), [0u8; 32]);
}

#[test]
fn agile_extend_refuses_to_leave_a_bank_behind() {
    let mut banks = Banks::new(&[Alg::Sha1, Alg::Sha256]).unwrap();
    let d256 = [0u8; 32];
    // Only the SHA-256 digest supplied: the SHA-1 bank would keep a history
    // that no longer matches the SHA-256 one.
    assert_eq!(banks.extend(7, &[(Alg::Sha256.id(), &d256[..])]), Err(PcrError::MissingBank(Alg::Sha1.id())));
    assert_eq!(banks.read(Alg::Sha1, 7).unwrap(), [0u8; 20]);
    assert_eq!(banks.read(Alg::Sha256, 7).unwrap(), [0u8; 32]);
}

#[test]
fn agile_extend_refuses_a_bank_that_is_not_allocated() {
    let mut banks = Banks::new(&[Alg::Sha256]).unwrap();
    let d256 = [0u8; 32];
    let d1 = [0u8; 20];
    assert_eq!(banks.extend(7, &[(Alg::Sha256.id(), &d256[..]), (Alg::Sha1.id(), &d1[..])]),
               Err(PcrError::UnknownBank(Alg::Sha1.id())));
}

#[test]
fn agile_extend_refuses_a_digest_sized_for_another_bank() {
    let mut banks = Banks::new(&[Alg::Sha1, Alg::Sha256]).unwrap();
    let wrong = [0u8; 32];
    let right = [0u8; 32];
    // A 32-byte value offered to the SHA-1 bank: right length for the other
    // bank, wrong for this one.
    assert_eq!(banks.extend(7, &[(Alg::Sha1.id(), &wrong[..]), (Alg::Sha256.id(), &right[..])]),
               Err(PcrError::BadDigestLen { expected: 20, got: 32 }));
    // Nothing moved: validation completes before any bank is written.
    assert_eq!(banks.read(Alg::Sha1, 7).unwrap(), [0u8; 20]);
    assert_eq!(banks.read(Alg::Sha256, 7).unwrap(), [0u8; 32]);
}

#[test]
fn bank_sets_are_bounded_and_unique() {
    assert_eq!(Banks::new(&[]).err(), Some(PcrError::BadBankSet));
    assert_eq!(Banks::new(&[Alg::Sha256, Alg::Sha256]).err(), Some(PcrError::BadBankSet));
    let many: Vec<Alg> = vec![Alg::Sha1, Alg::Sha256, Alg::Sha384, Alg::Sha512, Alg::Sm3];
    assert!(Banks::new(&many).is_ok());
}

#[test]
fn an_unsupported_bank_cannot_be_extended_silently() {
    let mut banks = Banks::new(&[Alg::Sm3]).unwrap();
    let d = [0u8; 32];
    assert_eq!(banks.extend(0, &[(Alg::Sm3.id(), &d[..])]), Err(PcrError::UnsupportedAlg(Alg::Sm3.id())));
    assert_eq!(extend_value(Alg::Sm3, &d, &d), Err(PcrError::UnsupportedAlg(Alg::Sm3.id())));
}
