//! The tweak sequence and the key split, stated as assertions.
//!
//! A tweak that never advances, or that advances by a big-endian shift, agrees
//! with itself on decryption and with nobody else. Neither shows up in a
//! round-trip, so both are asserted directly here; the field arithmetic's
//! actual numbers are pinned by the published vectors in the cipher crates.

use alloc::vec::Vec;

use super::toy::{data, key, Toy};
use crate::cipher::BLOCK_LEN;
use crate::xts::{unit_tweak, Xts, XtsError};

fn wide_key(seed: u8) -> Vec<u8> {
    let mut k = key(seed).to_vec();
    k.extend_from_slice(&key(seed.wrapping_add(1)));
    k
}

fn cipher(seed: u8) -> Xts<Toy> { Xts::new(&wide_key(seed)).expect("two supported halves") }

#[test]
fn every_length_from_one_block_up_round_trips_at_its_exact_length() {
    let x = cipher(1);
    let tweak = unit_tweak(7);
    for n in BLOCK_LEN..=(4 * BLOCK_LEN + 3) {
        let src = data(n);
        let mut buf = src.clone();
        x.encrypt(&tweak, &mut buf).expect("at least one block");
        assert_eq!(buf.len(), n, "length {n} changed");
        assert_ne!(buf, src, "length {n} was not encrypted at all");
        x.decrypt(&tweak, &mut buf).expect("at least one block");
        assert_eq!(buf, src, "length {n}");
    }
}

#[test]
fn the_tweak_advances_between_blocks() {
    // Two identical plaintext blocks in one unit must not encrypt alike; if
    // they do, the tweak is being reused and the mode has become ECB.
    let x = cipher(2);
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0xA5u8; BLOCK_LEN]);
    buf.extend_from_slice(&[0xA5u8; BLOCK_LEN]);
    x.encrypt(&unit_tweak(0), &mut buf).unwrap();
    assert_ne!(&buf[..BLOCK_LEN], &buf[BLOCK_LEN..], "the tweak did not advance");
}

#[test]
fn different_units_encrypt_the_same_bytes_differently() {
    let x = cipher(3);
    let src = data(2 * BLOCK_LEN);
    let mut a = src.clone();
    let mut b = src.clone();
    x.encrypt(&unit_tweak(0), &mut a).unwrap();
    x.encrypt(&unit_tweak(1), &mut b).unwrap();
    assert_ne!(a, b, "the unit number reached nothing");
    // And the units do not decrypt under each other, which is the property a
    // storage layer relies on when it seeks.
    let mut wrong = a.clone();
    x.decrypt(&unit_tweak(1), &mut wrong).unwrap();
    assert_ne!(wrong, src);
}

#[test]
fn the_two_halves_of_the_key_are_used_for_different_jobs() {
    // A construction that fed the same half to both the data and the tweak
    // cipher would still round-trip. Swapping the halves must change the
    // output; if it does not, only one of them is reaching the transform.
    let k = wide_key(4);
    let mut swapped = k[BLOCK_LEN..].to_vec();
    swapped.extend_from_slice(&k[..BLOCK_LEN]);
    let src = data(2 * BLOCK_LEN);

    let mut a = src.clone();
    Xts::<Toy>::new(&k).unwrap().encrypt(&unit_tweak(5), &mut a).unwrap();
    let mut b = src.clone();
    Xts::<Toy>::new(&swapped).unwrap().encrypt(&unit_tweak(5), &mut b).unwrap();
    assert_ne!(a, b, "the halves are interchangeable, so one of them is unused");
}

#[test]
fn the_key_widths_the_split_admits_and_the_ones_it_refuses() {
    // The mode's width is TWICE the cipher's, so a buffer the cipher would
    // accept whole is not a key here.
    assert!(Xts::<Toy>::new(&[0u8; 16]).is_ok(), "two 8-byte halves");
    assert!(Xts::<Toy>::new(&[0u8; 32]).is_ok(), "two 16-byte halves");
    for bad in [0usize, 1, 15, 17, 24, 31, 64] {
        assert!(matches!(Xts::<Toy>::new(&alloc::vec![0u8; bad]), Err(XtsError::BadKeyLength)),
            "a {bad}-byte key must not split into two usable halves");
    }
}

#[test]
fn a_unit_shorter_than_a_block_is_refused_rather_than_padded() {
    let x = cipher(6);
    let mut short = data(BLOCK_LEN - 1);
    assert_eq!(x.encrypt(&unit_tweak(0), &mut short).unwrap_err(), XtsError::TooShort);
    assert_eq!(x.decrypt(&unit_tweak(0), &mut short).unwrap_err(), XtsError::TooShort);
}

#[test]
fn the_unit_tweak_is_little_endian() {
    // A big-endian unit number is the classic wrong turn: it agrees on unit 0
    // and on nothing else, and no round-trip notices.
    assert_eq!(unit_tweak(1)[0], 1);
    assert_eq!(unit_tweak(1)[BLOCK_LEN - 1], 0);
    assert_eq!(unit_tweak(0x0102_0304), [4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}
