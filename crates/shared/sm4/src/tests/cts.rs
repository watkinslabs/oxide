//! SM4 chaining with ciphertext stealing, pinned to the published vector set.
//!
//! The 32-, 48- and 64-byte entries are the ones that matter most: their
//! lengths divide evenly, so an implementation that skips the last-two-block
//! exchange when nothing needs stealing still round-trips against itself and
//! disagrees with all three of them.

use alloc::vec::Vec;

use super::hex;
use blockcipher::cbc;
use blockcipher::cipher::BlockCipher;
use crate::block::Sm4;

/// The published vectors state no IV, which is an IV of zeroes.
const ZERO_IV: [u8; 16] = [0u8; 16];

fn check<const N: usize>(key: &str, pt: &str, ct: &str) {
    let k: [u8; 16] = hex(key);
    let plain: [u8; N] = hex(pt);
    let cipher: [u8; N] = hex(ct);

    let c = Sm4::from_key(&k).expect("the single SM4 key width");
    let mut buf: Vec<u8> = plain.to_vec();
    cbc::cts_encrypt(&c, &ZERO_IV, &mut buf).expect("at least one block");
    assert_eq!(buf.as_slice(), cipher.as_slice(), "encryption");
    cbc::cts_decrypt(&c, &ZERO_IV, &mut buf).expect("at least one block");
    assert_eq!(buf.as_slice(), plain.as_slice(), "decryption");
}

#[test]
fn seventeen_bytes() {
    check::<17>(
        "636869636b656e207465726979616b69",
        "4920776f756c64206c696b652074686520",
        "05fe23ee17a28998bc970a0b5467cad7d6");
}

#[test]
fn thirty_one_bytes() {
    check::<31>(
        "636869636b656e207465726979616b69",
        "4920776f756c64206c696b65207468652047656e6572616c20476175277320",
        "1546e495a4ecf0b849d66a9d89c7fd70d671c8c04d527c6693f770bba83fa3");
}

#[test]
fn thirty_two_bytes_exactly_two_blocks() {
    check::<32>(
        "636869636b656e207465726979616b69",
        "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
        "89c7993f87695cd3016abfd43f7902a3d671c8c04d527c6693f770bba83fa3cf");
}

#[test]
fn forty_seven_bytes() {
    check::<47>(
        "636869636b656e207465726979616b69",
        concat!(
        "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
        "6869636b656e2c20706c656173652c",
    ),
        concat!(
        "d671c8c04d527c6693f770bba83fa3cfd3e1dcebfa041199decf6f4d7b09927f",
        "89c7993f87695cd3016abfd43f7902",
    ));
}

#[test]
fn forty_eight_bytes_exactly_three_blocks() {
    check::<48>(
        "636869636b656e207465726979616b69",
        concat!(
        "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
        "6869636b656e2c20706c656173652c20",
    ),
        concat!(
        "d671c8c04d527c6693f770bba83fa3cf9abd7bfe82abcc7fbd99210c5e4ded20",
        "89c7993f87695cd3016abfd43f7902a3",
    ));
}

#[test]
fn sixty_four_bytes_exactly_four_blocks() {
    check::<64>(
        "636869636b656e207465726979616b69",
        concat!(
        "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
        "6869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e",
    ),
        concat!(
        "d671c8c04d527c6693f770bba83fa3cf89c7993f87695cd3016abfd43f7902a3",
        "5819a48fa9685e6b2c0f81601598274f9abd7bfe82abcc7fbd99210c5e4ded20",
    ));
}
