// RFC 8439 test vectors for the ChaCha20 block function. If this drifts, every
// byte `getrandom(2)` and `/dev/urandom` hand out is wrong in a way no
// statistical test would catch.

use super::*;

/// RFC 8439 §2.3.2 key: 00 01 02 ... 1f.
fn rfc_key() -> [u32; KEY_WORDS] {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() { *b = i as u8; }
    key_from_bytes(&bytes)
}

fn key_from_bytes(b: &[u8; 32]) -> [u32; KEY_WORDS] {
    let mut k = [0u32; KEY_WORDS];
    for i in 0..KEY_WORDS {
        k[i] = u32::from_le_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
    }
    k
}

#[test]
fn rfc8439_section_2_3_2_block_vector() {
    // Nonce 00:00:00:09 00:00:00:4a 00:00:00:00, counter 1.
    let out = block(&rfc_key(), 1, [0x0900_0000, 0x4a00_0000, 0x0000_0000]);
    let expect: [u8; 64] = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
        0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
        0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
        0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    ];
    assert_eq!(out, expect, "ChaCha20 block diverged from RFC 8439 §2.3.2");
}

#[test]
fn rfc8439_appendix_a_1_test_vector_1() {
    // All-zero key and nonce, counter 0.
    let out = block(&[0u32; KEY_WORDS], 0, [0, 0, 0]);
    let expect: [u8; 32] = [
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
        0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
        0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
        0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
    ];
    assert_eq!(&out[..32], &expect[..]);
}

#[test]
fn rfc8439_appendix_a_1_test_vector_2_counter_one() {
    let out = block(&[0u32; KEY_WORDS], 1, [0, 0, 0]);
    let expect: [u8; 16] = [
        0x9f, 0x07, 0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a,
        0x98, 0xba, 0x97, 0x7c, 0x73, 0x2d, 0x08, 0x0d,
    ];
    assert_eq!(&out[..16], &expect[..]);
}

#[test]
fn counter_and_nonce_change_the_block() {
    let k = rfc_key();
    let a = block(&k, 0, [0, 0, 0]);
    let b = block(&k, 1, [0, 0, 0]);
    let c = block(&k, 0, [1, 0, 0]);
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
}

#[test]
fn key_from_reads_the_first_32_bytes_little_endian() {
    let mut b = [0u8; BLOCK_BYTES];
    b[0] = 0x78; b[1] = 0x56; b[2] = 0x34; b[3] = 0x12;
    b[28] = 0xef; b[29] = 0xbe; b[30] = 0xad; b[31] = 0xde;
    let k = key_from(&b);
    assert_eq!(k[0], 0x1234_5678);
    assert_eq!(k[7], 0xdead_beef);
}
