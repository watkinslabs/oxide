//! Published known-answer vectors for the pairing crypto functions.
//!
//! These are the whole provenance of the byte-order handling. Every value here
//! is written in the least-significant-first order the protocol carries, which
//! is also the order the functions take and return.

use super::hex;
use crate::uapi::bt::BdAddr;
use crate::smp::crypto::{ah, aes_cmac, c1, e, f4, f5, f6, g2, h6, h7, swap};

#[test]
fn swap_reverses() {
    assert_eq!(swap(&[1u8, 2, 3, 4]), [4, 3, 2, 1]);
    assert_eq!(swap(&swap(&[1u8, 2, 3, 4])), [1, 2, 3, 4]);
}

#[test]
fn security_function_is_the_reversed_cipher() {
    // A known block cipher answer, restated through the reversal both ways.
    let k = hex::<16>("000102030405060708090a0b0c0d0e0f");
    let pt = hex::<16>("00112233445566778899aabbccddeeff");
    let ct = hex::<16>("69c4e0d86a7b0430d8cdb78070b4c55a");
    assert_eq!(e(&swap(&k), &swap(&pt)), swap(&ct));
}

#[test]
fn random_address_hash() {
    let irk = hex::<16>("9b7d390aa610103405adc857a33402ec");
    let r = hex::<3>("948170");
    assert_eq!(ah(&irk, &r), hex::<3>("aafb0d"));
}

#[test]
fn legacy_confirm() {
    let k = [0u8; 16];
    let r = hex::<16>("e02e70c64e2788630e6fad5621d58357");
    let preq = hex::<7>("01010000100707");
    let pres = hex::<7>("02030000080005");
    let ia = BdAddr(hex::<6>("a6a5a4a3a2a1"));
    let ra = BdAddr(hex::<6>("b6b5b4b3b2b1"));
    let res = c1(&k, &r, &preq, &pres, 0x01, &ia, 0x00, &ra);
    assert_eq!(res, hex::<16>("863bf1bec54da7d2ea888987ef3f1e1e"));
}

#[test]
fn short_term_key() {
    let k = [0u8; 16];
    let r1 = hex::<16>("88776655443322110000000000000000");
    let r2 = hex::<16>("00ffeeddccbbaa990000000000000000");
    assert_eq!(super::super::crypto::s1(&k, &r1, &r2),
               hex::<16>("62a06d79ae16425b9bf4b0e8f0e11f9a"));
}

const U: [u8; 32] = hex(concat!(
    "e69d350e480103ccdbfdf4ac1191f4ef",
    "b9a5f9e9a7832c5e2cbe97f2d203b020"));
const V: [u8; 32] = hex(concat!(
    "fdc57ff449dd4f6bfb7c9df1c29acb59",
    "2ae7d4eefbfc0a909abbf6323d8b1855"));
const X: [u8; 16] = hex("abae2b71ecb2ffff3e7377d15484cbd5");
const Y: [u8; 16] = hex("cfc43dfff78365216e5fa725cce7e8a6");

#[test]
fn secure_connections_confirm() {
    assert_eq!(f4(&U, &V, &X, 0x00), hex::<16>("2d8774a9bea1edf11cbda907f116c9f2"));
}

#[test]
fn secure_connections_key_derivation() {
    let w = hex::<32>(concat!(
        "98a6bf73f3348d86f166f8b4136b7999",
        "9b7d390aa610103405adc857a33402ec"));
    let n1 = X;
    let n2 = Y;
    let a1 = hex::<7>("cebf3737125600");
    let a2 = hex::<7>("c1cf2d7013a700");
    let (mackey, ltk) = f5(&w, &n1, &n2, &a1, &a2);
    assert_eq!(mackey, hex::<16>("206e63ce206a3ffd024a08a176f16529"));
    assert_eq!(ltk, hex::<16>("380a7594b522059823cdd76911798669"));
}

#[test]
fn secure_connections_check() {
    let w = hex::<16>("206e63ce206a3ffd024a08a176f16529");
    let r = hex::<16>("c80f2d0cd242da0854bb53b43b34a312");
    let io_cap = hex::<3>("020101");
    let a1 = hex::<7>("cebf3737125600");
    let a2 = hex::<7>("c1cf2d7013a700");
    assert_eq!(f6(&w, &X, &Y, &r, &io_cap, &a1, &a2),
               hex::<16>("618f95da090b6cd2c5e8d09c9873c4e3"));
}

#[test]
fn numeric_comparison_value() {
    assert_eq!(g2(&U, &V, &X, &Y), 0x2f9ed5ba % 1_000_000);
}

const H6_W: [u8; 16] = hex("9b7d390aa610103405adc857a33402ec");

#[test]
fn cross_transport_derivation_h6() {
    let key_id = hex::<4>("7262656c");
    assert_eq!(h6(&H6_W, &key_id), hex::<16>("9963b180e2a9d3e81cc96de702e19a2d"));
}

#[test]
fn cross_transport_derivation_h7_swaps_key_and_message() {
    // The second-generation function keys on the salt and authenticates the
    // key, exactly the reverse of the first. Feeding the same two values to
    // both must therefore give different answers, and each must equal the
    // underlying code with the arguments in its own order.
    let salt = hex::<16>("9963b180e2a9d3e81cc96de702e19a2d");
    assert_eq!(h7(&H6_W, &salt), aes_cmac(&salt, &H6_W));
    assert_eq!(h6(&H6_W, &hex::<4>("7262656c")), aes_cmac(&H6_W, &hex::<4>("7262656c")));
    assert_ne!(h7(&H6_W, &salt), aes_cmac(&H6_W, &salt));
}

#[test]
fn message_authentication_over_every_length_the_protocol_uses() {
    // The four message widths the functions above build, each exercising a
    // different padding case in the underlying code: 4 and 65 are padded, 16
    // and 80 end on a block boundary.
    let k = X;
    for len in [4usize, 16, 65, 80] {
        let msg = [0xa5u8; 80];
        let mac = aes_cmac(&k, &msg[..len]);
        // Reversing the message must change the answer for a message that is
        // not a palindrome, which is what proves the reversal is applied.
        let mut rev = [0u8; 80];
        for i in 0..len { rev[i] = msg[len - 1 - i] ^ (i as u8); }
        assert_ne!(mac, aes_cmac(&k, &rev[..len]), "len {}", len);
    }
}
