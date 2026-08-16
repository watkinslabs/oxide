//! CBC and CBC with ciphertext stealing, against the published CS3 vectors
//! (RFC 3962 Appendix B — key "chicken teriyaki", all-zero IV).
//!
//! The 64-byte case is the one that pins the convention: its length is an
//! exact multiple of the block size, and an implementation that skips the
//! final swap there produces the plain CBC ciphertext instead.

use super::hex;
use crate::block::AesKey;
use crate::cbc::{self, CbcError};

const KEY: &[u8; 16] = b"chicken teriyaki";
const ZERO_IV: [u8; 16] = [0; 16];

fn key() -> AesKey { AesKey::new(KEY).unwrap() }

fn cts(plain: &[u8], want: &[u8]) {
    let mut buf = alloc::vec::Vec::from(plain);
    cbc::cts_encrypt(&key(), &ZERO_IV, &mut buf).unwrap();
    assert_eq!(&buf[..], want, "encrypt");
    cbc::cts_decrypt(&key(), &ZERO_IV, &mut buf).unwrap();
    assert_eq!(&buf[..], plain, "decrypt");
}

/// Exactly one block: plain CBC, no steal and no swap.
#[test]
fn rfc3962_one_block_is_plain_cbc() {
    let want: [u8; 16] = hex("97687268d6ecccc0c07b25e25ecfe584");
    cts(b"I would like the", &want);
    let mut plain = *b"I would like the";
    let mut iv = ZERO_IV;
    cbc::encrypt(&key(), &mut iv, &mut plain).unwrap();
    assert_eq!(plain, want);
}

/// A length that is not a multiple of the block: the tail is stolen.
#[test]
fn rfc3962_partial_final_block() {
    let want: [u8; 63] = hex(
        "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a8\
45158e8be0cf13f15c994bfcbacb1e9e9dad8bbb96c4cdc03bc103e1a194bb");
    cts(b"I would like the General Gau's Chicken, please, and wonton soup", &want);
}

/// A length that IS a multiple of the block: the last two ciphertext blocks
/// are still swapped. Omitting the swap here is the classic divergence.
#[test]
fn rfc3962_whole_blocks_still_swap() {
    let want: [u8; 64] = hex(
        "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a8\
4807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8");
    cts(b"I would like the General Gau's Chicken, please, and wonton soup.", &want);
    // The unswapped CBC ciphertext of the same input differs in exactly the
    // last two blocks, which is what the swap is.
    let mut cbc_only = alloc::vec::Vec::from(
        &b"I would like the General Gau's Chicken, please, and wonton soup."[..]);
    let mut iv = ZERO_IV;
    cbc::encrypt(&key(), &mut iv, &mut cbc_only).unwrap();
    assert_eq!(&cbc_only[..32], &want[..32]);
    assert_eq!(&cbc_only[32..48], &want[48..64]);
    assert_eq!(&cbc_only[48..64], &want[32..48]);
}

#[test]
fn cbc_round_trips_and_refuses_a_partial_block() {
    let mut buf = [0u8; 48];
    for (i, b) in buf.iter_mut().enumerate() { *b = i as u8; }
    let plain = buf;
    let mut iv = [9u8; 16];
    let mut e = iv;
    cbc::encrypt(&key(), &mut e, &mut buf).unwrap();
    assert_ne!(buf, plain);
    cbc::decrypt(&key(), &mut iv, &mut buf).unwrap();
    assert_eq!(buf, plain);
    let mut short = [0u8; 17];
    assert_eq!(cbc::encrypt(&key(), &mut iv, &mut short), Err(CbcError::NotBlockAligned));
}

#[test]
fn stealing_refuses_less_than_one_block() {
    let mut short = [0u8; 15];
    assert_eq!(cbc::cts_encrypt(&key(), &ZERO_IV, &mut short), Err(CbcError::TooShort));
    assert_eq!(cbc::cts_decrypt(&key(), &ZERO_IV, &mut short), Err(CbcError::TooShort));
}

/// Every length a filename can take round-trips, including the two-block
/// boundary where the decrypt path chooses the IV rather than a stored block.
#[test]
fn every_length_round_trips() {
    for n in 16..=64usize {
        let plain: alloc::vec::Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
        let mut buf = plain.clone();
        cbc::cts_encrypt(&key(), &ZERO_IV, &mut buf).unwrap();
        assert_eq!(buf.len(), n);
        cbc::cts_decrypt(&key(), &ZERO_IV, &mut buf).unwrap();
        assert_eq!(buf, plain, "length {n}");
    }
}
