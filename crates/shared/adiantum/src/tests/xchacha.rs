//! The published vectors for the abbreviated core and for the extended-nonce
//! construction, at both round counts.

use crate::chacha::{self, ROUNDS_12, ROUNDS_20};
use super::hex;

const HCHACHA_KEY: [u8; 32] = hex::<32>(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

#[test]
fn abbreviated_core() {
    let nonce = hex::<16>("000000090000004a0000000031415927");
    let sub = chacha::hchacha(&HCHACHA_KEY, &nonce, ROUNDS_20);
    let mut got = [0u8; 32];
    for i in 0..8 { got[4 * i..4 * i + 4].copy_from_slice(&sub[i].to_le_bytes()); }
    let want = hex::<32>("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
    assert_eq!(got, want);
}

const XC20_KEY: [u8; 32] = hex::<32>(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
const XC20_PT: [u8; 304] = hex::<304>(
    "5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973\
    20616c736f206b6e6f776e2061732074686520417369617469632077696c6420\
    646f672c2072656420646f672c20616e642077686973746c696e6720646f672e\
    2049742069732061626f7574207468652073697a65206f662061204765726d61\
    6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061\
    206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c\
    757369766520616e6420736b696c6c6564206a756d70657220697320636c6173\
    736966696564207769746820776f6c7665732c20636f796f7465732c206a6163\
    6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963\
    2066616d696c792043616e696461652e");
const XC20_CT: [u8; 304] = hex::<304>(
    "4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e9\
    8d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d\
    4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0da\
    ece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e744\
    3056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b74814240\
    7c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c\
    09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae\
    577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486c\
    cb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a663\
    93b93111c1a55dd7421a10184974c7c5");

#[test]
fn extended_nonce_20() {
    // 24-byte nonce, then an all-zero 8-byte stream position (counter 0).
    let mut iv = [0u8; 32];
    iv[..24].copy_from_slice(&hex::<24>("404142434445464748494a4b4c4d4e4f5051525354555658"));
    let mut buf = XC20_PT;
    chacha::xchacha_xor(&XC20_KEY, &iv, &mut buf, ROUNDS_20);
    assert_eq!(buf, XC20_CT);
    chacha::xchacha_xor(&XC20_KEY, &iv, &mut buf, ROUNDS_20);
    assert_eq!(buf, XC20_PT);
}

const XC12_KEY: [u8; 32] = hex::<32>(
    "79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4");
const XC12_IV: [u8; 32] = hex::<32>(
    "b33ffd3096479bcfbc9aee49417688a0a2554f8d953894190000000000000000");
const XC12_PT: [u8; 29] = hex::<29>(
    "0000000000000000000000000000000000000000000000000000000000");
const XC12_CT: [u8; 29] = hex::<29>(
    "1b787fd7a14168ab3d3fd17b6956b2d543ceebaf36f0299d3afb18ae1b");

#[test]
fn extended_nonce_12() {
    let mut buf = XC12_PT;
    chacha::xchacha_xor(&XC12_KEY, &XC12_IV, &mut buf, ROUNDS_12);
    assert_eq!(buf, XC12_CT);
}
