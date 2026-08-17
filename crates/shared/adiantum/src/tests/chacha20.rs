//! The published twenty-round vectors: the block function, and the stream it
//! generates.

use crate::chacha::{self, State, CHACHA_BLOCK_LEN, ROUNDS_20};
use super::hex;

const KEY: [u8; 32] = hex::<32>(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

#[test]
fn block_function() {
    // Counter 1; nonce 00:00:00:09 00:00:00:4a 00:00:00:00.
    let iv = hex::<16>("01000000000000090000004a00000000");
    let mut st = State::new(&KEY, &iv);
    let mut out = [0u8; CHACHA_BLOCK_LEN];
    chacha::block(&mut st, &mut out, ROUNDS_20);
    let want = hex::<64>(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
        d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    assert_eq!(out, want);
    // Producing a block advances the counter word.
    assert_eq!(st.x[12], 2);
}

const SUNSCREEN_PT: [u8; 114] = hex::<114>(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
    73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
    6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
    637265656e20776f756c642062652069742e");

const SUNSCREEN_CT: [u8; 114] = hex::<114>(
    "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
    f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
    07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
    5af90bbf74a35be6b40b8eedf2785e42874d");

const SUNSCREEN_KS: [u8; 114] = hex::<114>(
    "224f51f3401bd9e12fde276fb8631ded8c131f823d2c06e27e4fcaec9ef3cf78\
    8a3b0aa372600a92b57974cded2b9334794cba40c63e34cdea212c4cf07d41b7\
    69a6749f3f630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53ac40c5945\
    398b6eda1a832c89c167eacd901d7e2bf363");

#[test]
fn keystream_and_stream_xor() {
    // Counter 1; nonce 00:00:00:00 00:00:00:4a 00:00:00:00.
    let iv = hex::<16>("01000000000000000000004a00000000");

    // The keystream itself, taken by running the stream over zeros.
    let mut ks = [0u8; SUNSCREEN_KS.len()];
    let mut st = State::new(&KEY, &iv);
    chacha::xor_stream(&mut st, &mut ks, ROUNDS_20);
    assert_eq!(ks, SUNSCREEN_KS);

    let mut buf = SUNSCREEN_PT;
    let mut st = State::new(&KEY, &iv);
    chacha::xor_stream(&mut st, &mut buf, ROUNDS_20);
    assert_eq!(buf, SUNSCREEN_CT);

    let mut st = State::new(&KEY, &iv);
    chacha::xor_stream(&mut st, &mut buf, ROUNDS_20);
    assert_eq!(buf, SUNSCREEN_PT);
}
