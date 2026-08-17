//! SM4-XTS, pinned to the published vector set for the pairing.
//!
//! The interesting entries are the last two: a 512-byte unit, long enough that
//! the tweak's field arithmetic must carry correctly across many blocks, and a
//! 189-byte unit, which is not a whole number of blocks and so exercises the
//! stolen final pair. A tweak that advanced by a big-endian shift, or a steal
//! that used the wrong tweak for the penultimate block, decrypts its own
//! output perfectly and disagrees with every one of these.

use alloc::vec::Vec;

use super::hex;
use crate::mode::Sm4Xts;

/// (key, unit tweak, plaintext, ciphertext) — the sizes differ per vector, so
/// each is checked by its own call rather than through one array type.
fn check<const K: usize, const N: usize>(key: &str, iv: &str, pt: &str, ct: &str) {
    let k: [u8; K] = hex(key);
    let unit: [u8; 16] = hex(iv);
    let plain: [u8; N] = hex(pt);
    let cipher: [u8; N] = hex(ct);

    let x = Sm4Xts::new(&k).expect("two SM4 key halves");
    let mut buf: Vec<u8> = plain.to_vec();
    x.encrypt(&unit, &mut buf).expect("at least one block");
    assert_eq!(buf.as_slice(), cipher.as_slice(), "encryption");
    x.decrypt(&unit, &mut buf).expect("at least one block");
    assert_eq!(buf.as_slice(), plain.as_slice(), "decryption");
}

#[test]
fn all_zero_key_and_unit() {
    check::<32, 32>(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "d9b421f731c894fdc35b77291fe4e3b02a1fb76698d59f0e51376c4ada5bc75d");
}

#[test]
fn repeated_key_halves() {
    check::<32, 32>(
        "1111111111111111111111111111111122222222222222222222222222222222",
        "33333333330000000000000000000000",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "a74d726c11196a32be04e001ff29d0c7932f9f3ec29bfcb64dd17f63cbd3ea31");
}

#[test]
fn descending_first_half() {
    check::<32, 32>(
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f022222222222222222222222222222222",
        "33333333330000000000000000000000",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "7f76088effadf70c02ea9f95da0628d351bfcb9eac0563bcf17b710dab0a9826");
}

#[test]
fn five_hundred_and_twelve_bytes() {
    check::<32, 512>(
        "2718281828459045235360287471352631415926535897932384626433832795",
        "00000000000000000000000000000000",
        concat!(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    ),
        concat!(
        "54dd65b6326faea8fad1a83c63614af39f721d8dfe177a30b66abf6a449980e1",
        "cdbe06afb73336f37a4d39de964a30d7d04a3799169c60258f6b748a61861aa5",
        "ec92a2c15b2b7c615a42aba499bbd6b71db9c789b2182089a25dd3df800ed186",
        "4d19f7ed45fd17a9480b0fb82d9b7fc3ed57e9a1140eaa778dd2dd679e3edc3d",
        "c4d55c950ebc531d9592f7c4638256d56518292a20af98fdd3a63600350a70ab",
        "5a40f4c285037ca01f251f19ecae0329ff77ad88cd5a4cdea2aeabc22148ffbd",
        "239bd10515bde1131dec8404e443dc763140d5f22bf33e0c6872d6b81d630f6f",
        "00cdd058fe80f9cbfb77707f93cee2ca92b915b8304027c190a84e2d65e018cc",
        "6a387d3766acdb28253284e8db9acf8f52280ddc6d0033d2ccaaa4f9aeff1236",
        "69bc024fd6768edf8bc1f8d622c19c609ef97f609190cd110241e7fb084ed894",
        "2da1f9b9cf1b514b61a388b30ea61a4a745b381ee7ad6c4db1275453b8413f98",
        "df6e4a40986ee4b59af5dfaecd301265179067a00d7ca35ab95abd617adea28e",
        "c1c26a97de28b8bfe30120d6aefbd258c59e42d161e8065a78106bdca5cd90fb",
        "3aac4e93866c8a7f9676860a79145bd92e02e819a90be0b97cc522b32106856f",
        "df0e54d88e4624155a2f1c14eaeaa163f858e99a806e791acd82f1b0e29f0028",
        "a4c38e976f571a93f4fd57d787c24db0e01ca304e5a5c4dd50cf8bdbf491e57c",
    ));
}

#[test]
fn a_unit_that_is_not_whole_blocks() {
    check::<32, 189>(
        "6249775724709369995957496696762702884197169399375105820974944592",
        "ff000000000000000000000000000000",
        concat!(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7f8f9fafbfc",
    ),
        concat!(
        "a29f9e4e71db283c800ef6b78e571cba90da3b6c220068301d630d9e6aad3755",
        "bc771ec9ad8330d527b26677183ca6399c0aaa1f02e1d5659b8dc5973dc50453",
        "7800e3b01a434eb7c49f38c57ba4706478e632d96544c564b8423599ff6675b0",
        "22d39b6e8dcf6a24fd92b71b04282a61dc962a207a2cf1f91215f04dcf2bde33",
        "41bce7858722b716021cd8a20f1fa3e9d84548e7be084e4e237984db4076f513",
        "78924a2ff91bf280257451459a777897d3e0c7c435672ae6b30d629f8b",
    ));
}
