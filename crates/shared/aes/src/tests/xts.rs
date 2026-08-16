//! XTS-AES against known answers.
//!
//! The first is the published IEEE 1619 vector whose keys are the digits of e
//! and pi; a 512-byte unit exercises the tweak's field multiplication 31 times,
//! which is what separates the little-endian shift the standard defines from
//! the big-endian one that agrees only on the first block.

use super::hex;
use crate::xts::{unit_tweak, Xts, XtsError};

/// The published data unit: keys from e and pi, plaintext 0x00..0xff twice.
fn ieee_key() -> [u8; 32] { hex("2718281828459045235360287471352631415926535897932384626433832795") }

fn counting_512() -> alloc::vec::Vec<u8> {
    (0..512usize).map(|i| (i % 256) as u8).collect()
}

#[test]
fn ieee1619_aes128_unit_zero() {
    let x = Xts::new(&ieee_key()).unwrap();
    let plain = counting_512();
    let mut buf = plain.clone();
    x.encrypt(&unit_tweak(0), &mut buf).unwrap();
    let head: [u8; 64] = hex(
        "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c\
c78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412");
    let tail: [u8; 32] = hex(
        "eb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568");
    assert_eq!(&buf[..64], &head[..]);
    assert_eq!(&buf[480..], &tail[..]);
    x.decrypt(&unit_tweak(0), &mut buf).unwrap();
    assert_eq!(buf, plain);
}

/// A 256-bit-per-half key with a non-zero unit number: the tweak is the unit
/// index enciphered under the second half, so a wrong index changes the whole
/// unit rather than one block.
#[test]
fn aes256_unit_seven() {
    let key: [u8; 64] = core::array::from_fn(|i| i as u8);
    let x = Xts::new(&key).unwrap();
    let plain: [u8; 32] = hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    let mut buf = plain;
    x.encrypt(&unit_tweak(7), &mut buf).unwrap();
    let want: [u8; 32] = hex("01fe7a5aa1bbb4d6a4d68de3ee01d18708f5303731d379d134bda21c22f04ee8");
    assert_eq!(buf, want);
    x.decrypt(&unit_tweak(7), &mut buf).unwrap();
    assert_eq!(buf, plain);
    // A different unit number gives entirely different ciphertext.
    let mut other = plain;
    x.encrypt(&unit_tweak(8), &mut other).unwrap();
    assert_ne!(other, want);
}

/// A unit that is not a whole number of blocks steals ciphertext and keeps its
/// exact length.
#[test]
fn partial_final_block_steals() {
    let key: [u8; 64] = core::array::from_fn(|i| i as u8);
    let x = Xts::new(&key).unwrap();
    let plain: [u8; 20] = hex("000102030405060708090a0b0c0d0e0f10111213");
    let mut buf = plain;
    x.encrypt(&unit_tweak(7), &mut buf).unwrap();
    assert_eq!(buf, hex::<20>("02e83cc0c8bdadb03d6c5e48f140e2a0b2d9289b"));
    x.decrypt(&unit_tweak(7), &mut buf).unwrap();
    assert_eq!(buf, plain);
}

#[test]
fn every_length_round_trips() {
    let key: [u8; 64] = core::array::from_fn(|i| (i * 3) as u8);
    let x = Xts::new(&key).unwrap();
    for n in 16..=80usize {
        let plain: alloc::vec::Vec<u8> = (0..n).map(|i| (i * 11 + 5) as u8).collect();
        let mut buf = plain.clone();
        x.encrypt(&unit_tweak(n as u128), &mut buf).unwrap();
        assert_eq!(buf.len(), n);
        x.decrypt(&unit_tweak(n as u128), &mut buf).unwrap();
        assert_eq!(buf, plain, "length {n}");
    }
}

#[test]
fn key_and_length_refusals() {
    assert!(matches!(Xts::new(&[0u8; 48]), Err(XtsError::BadKeyLength)));
    assert!(matches!(Xts::new(&[0u8; 16]), Err(XtsError::BadKeyLength)));
    let x = Xts::new(&[0u8; 32]).unwrap();
    let mut short = [0u8; 15];
    assert_eq!(x.encrypt(&unit_tweak(0), &mut short), Err(XtsError::TooShort));
    assert_eq!(x.decrypt(&unit_tweak(0), &mut short), Err(XtsError::TooShort));
}
