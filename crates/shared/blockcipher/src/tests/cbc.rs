//! The stealing rule, stated as an assertion rather than trusted.
//!
//! CS3 is CBC whose last two ciphertext blocks are exchanged, with the final
//! short block truncated to the message's length. The variants that skip the
//! exchange, or skip it when the length divides evenly, round-trip against
//! themselves perfectly — so a round-trip test cannot tell them apart and the
//! assertions here are about the SHAPE of the output, not about recovery.

use alloc::vec::Vec;

use super::toy::{data, key, Toy};
use crate::cbc::{self, CbcError};
use crate::cipher::{BlockCipher, BLOCK_LEN};

fn cts(iv: &[u8; BLOCK_LEN], src: &[u8]) -> Vec<u8> {
    let c = Toy::from_key(&key(9)).expect("a supported width");
    let mut buf = src.to_vec();
    cbc::cts_encrypt(&c, iv, &mut buf).expect("at least one block");
    buf
}

fn plain(iv: &[u8; BLOCK_LEN], src: &[u8]) -> Vec<u8> {
    let c = Toy::from_key(&key(9)).expect("a supported width");
    let mut buf = src.to_vec();
    let mut chain = *iv;
    cbc::encrypt(&c, &mut chain, &mut buf).expect("a whole number of blocks");
    buf
}

#[test]
fn stealing_exchanges_the_last_two_blocks_even_on_an_exact_multiple() {
    // The single most common divergence between implementations: CS3 applies
    // the exchange at every length above one block, including the ones where
    // there is nothing to steal.
    let iv = key(1);
    for blocks in 2..=5usize {
        let src = data(blocks * BLOCK_LEN);
        let want_from = plain(&iv, &src);
        let mut want = want_from.clone();
        let n = want.len();
        for i in 0..BLOCK_LEN { want.swap(n - BLOCK_LEN + i, n - 2 * BLOCK_LEN + i); }
        assert_eq!(cts(&iv, &src), want, "{blocks} whole blocks");
        assert_ne!(cts(&iv, &src), want_from, "the exchange is not a no-op");
    }
}

#[test]
fn one_block_is_plain_chaining_with_no_exchange() {
    let iv = key(2);
    let src = data(BLOCK_LEN);
    assert_eq!(cts(&iv, &src), plain(&iv, &src));
}

#[test]
fn stealing_preserves_the_exact_length_and_recovers_it() {
    let iv = key(4);
    let c = Toy::from_key(&key(9)).expect("a supported width");
    for n in BLOCK_LEN..=(4 * BLOCK_LEN + 7) {
        let src = data(n);
        let mut buf = src.clone();
        cbc::cts_encrypt(&c, &iv, &mut buf).expect("at least one block");
        assert_eq!(buf.len(), n, "length {n} changed");
        assert_ne!(buf, src, "length {n} was not encrypted at all");
        cbc::cts_decrypt(&c, &iv, &mut buf).expect("at least one block");
        assert_eq!(buf, src, "length {n}");
    }
}

#[test]
fn the_short_tail_is_the_head_of_the_block_before_it() {
    // The stolen bytes are the FIRST bytes of the penultimate ciphertext
    // block, not its last. Taking the tail instead round-trips against itself.
    let iv = key(5);
    let src = data(BLOCK_LEN + 5);
    let out = cts(&iv, &src);
    let mut padded = src.clone();
    padded.resize(2 * BLOCK_LEN, 0);
    let cbc_of_padded = plain(&iv, &padded);
    assert_eq!(&out[BLOCK_LEN..], &cbc_of_padded[..5],
        "the tail is the head of the penultimate ciphertext block");
}

#[test]
fn the_lengths_each_mode_refuses() {
    let c = Toy::from_key(&key(6)).expect("a supported width");
    let mut chain = key(0);
    let mut buf = data(BLOCK_LEN + 1);
    assert_eq!(cbc::encrypt(&c, &mut chain, &mut buf).unwrap_err(), CbcError::NotBlockAligned);
    assert_eq!(cbc::decrypt(&c, &mut chain, &mut buf).unwrap_err(), CbcError::NotBlockAligned);
    let mut short = data(BLOCK_LEN - 1);
    assert_eq!(cbc::cts_encrypt(&c, &chain, &mut short).unwrap_err(), CbcError::TooShort);
    assert_eq!(cbc::cts_decrypt(&c, &chain, &mut short).unwrap_err(), CbcError::TooShort);
}

#[test]
fn chaining_carries_the_iv_forward_so_a_split_call_matches_one_call() {
    // The out-parameter IV is the whole reason `encrypt` takes `&mut`: a
    // caller that chains two buffers must get the same bytes as one buffer.
    let c = Toy::from_key(&key(7)).expect("a supported width");
    let src = data(4 * BLOCK_LEN);
    let iv = key(8);

    let mut one = src.clone();
    let mut chain = iv;
    cbc::encrypt(&c, &mut chain, &mut one).unwrap();

    let mut two = src.clone();
    let mut chain2 = iv;
    let (a, b) = two.split_at_mut(2 * BLOCK_LEN);
    cbc::encrypt(&c, &mut chain2, a).unwrap();
    cbc::encrypt(&c, &mut chain2, b).unwrap();
    assert_eq!(two, one);
    assert_eq!(chain2, chain, "both leave the same trailing block");
}
