// The data unit number: carrying, the IV it produces, and the contiguity rule.

use crate::crypto::dun::{Dun, DUN_LIMBS};

#[test]
fn increment_carries_between_limbs() {
    let mut d = Dun::from_limbs([u64::MAX, 0, 0, 0]);
    d.increment(1);
    assert_eq!(*d.limbs(), [0, 1, 0, 0]);
}

#[test]
fn increment_carries_through_every_limb() {
    let mut d = Dun::from_limbs([u64::MAX; DUN_LIMBS]);
    d.increment(1);
    // The carry out of the top limb has nowhere to go and is dropped, which
    // is precisely the wrap the contiguity rule refuses to merge across.
    assert_eq!(*d.limbs(), [0; DUN_LIMBS]);
}

#[test]
fn iv_is_little_endian_per_limb() {
    let iv = Dun::from_limbs([0x0102_0304_0506_0708, 0, 0, 0x11]).to_iv();
    assert_eq!(&iv[..8], &[8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(iv[24], 0x11);
    assert_eq!(&iv[8..24], &[0u8; 16]);
}

#[test]
fn contiguous_run_merges() {
    let a = Dun::from_u64(100);
    assert!(a.is_contiguous(8, &Dun::from_u64(108)));
}

#[test]
fn discontiguous_run_does_not_merge() {
    let a = Dun::from_u64(100);
    assert!(!a.is_contiguous(8, &Dun::from_u64(109)));
    assert!(!a.is_contiguous(8, &Dun::from_u64(107)));
}

#[test]
fn contiguity_carries_between_limbs() {
    let a = Dun::from_limbs([u64::MAX - 1, 5, 0, 0]);
    assert!(a.is_contiguous(2, &Dun::from_limbs([0, 6, 0, 0])));
    assert!(!a.is_contiguous(2, &Dun::from_limbs([0, 5, 0, 0])));
}

#[test]
fn wrap_through_zero_is_not_contiguous() {
    // The arithmetic agrees the numbers are adjacent. They are not: the second
    // run reuses a keystream position the first already consumed, so a request
    // holding both would encrypt two different data units identically.
    let a = Dun::from_limbs([u64::MAX; DUN_LIMBS]);
    assert_eq!(a.advanced(1), Dun::ZERO);
    assert!(!a.is_contiguous(1, &Dun::ZERO));
}
