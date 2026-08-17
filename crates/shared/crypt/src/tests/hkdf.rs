// HKDF-SHA512 (RFC 5869) against known answers.
//
// RFC 5869's own vectors are SHA-256 and SHA-1; the values below are the same
// inputs run through HKDF-SHA512 by an independent implementation of the
// specification. Two of the properties they pin cannot be seen from a
// round-trip against ourselves:
//
// - The 82-byte output crosses the 64-byte digest boundary twice, so the
//   counter and the T(i-1) feedback are both exercised. A counter starting at
//   zero, or a chain that omits the feedback, changes bytes 64 onward only.
// - The absent-salt case must equal an all-zero salt of the hash's width.

use super::HkdfSha512;
use crate::hmac::hmac_sha512;

fn hex<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    assert_eq!(b.len(), 2 * N);
    let d = |c: u8| -> u8 {
        match c { b'0'..=b'9' => c - b'0', b'a'..=b'f' => c - b'a' + 10, _ => panic!("hex") }
    };
    let mut out = [0u8; N];
    for i in 0..N { out[i] = (d(b[2 * i]) << 4) | d(b[2 * i + 1]); }
    out
}

const IKM: [u8; 22] = [0x0b; 22];
const SALT: [u8; 13] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b, 0x0c];
const INFO: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

/// Extract is HMAC with the SALT as the key. The reversed argument order is
/// self-consistent and wrong, and only a vector catches it.
#[test]
fn extract_keys_the_mac_with_the_salt() {
    let want: [u8; 64] = hex(
        "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26\
c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237");
    assert_eq!(hmac_sha512(&SALT, &IKM), want);
}

#[test]
fn expand_82_bytes_spans_two_counter_steps() {
    let k = HkdfSha512::extract(&SALT, &IKM);
    let mut okm = [0u8; 82];
    assert!(k.expand(&[&INFO], &mut okm));
    let want: [u8; 82] = hex(
        "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c14815793\
38da362cb8d9f925d7cbcce0dff7098769cf15959867d571c1715450cb530137be3fb62f3cf3\
2b84feba8f1eb1b563e20d97");
    assert_eq!(okm, want);
}

#[test]
fn absent_salt_is_a_zero_block_of_the_hash_width() {
    let k = HkdfSha512::extract(&[], &IKM);
    let mut okm = [0u8; 42];
    assert!(k.expand(&[], &mut okm));
    let want: [u8; 42] = hex(
        "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90f\
ff22d04836d0e2343bac");
    assert_eq!(okm, want);
    let explicit = HkdfSha512::extract(&[0u8; 64], &IKM);
    let mut okm2 = [0u8; 42];
    assert!(explicit.expand(&[], &mut okm2));
    assert_eq!(okm, okm2);
}

/// The info string split across pieces is the same as one buffer — how the
/// filesystem prefixes a context byte without joining allocations.
#[test]
fn info_pieces_join() {
    let k = HkdfSha512::extract(&SALT, &IKM);
    let mut a = [0u8; 40];
    let mut b = [0u8; 40];
    assert!(k.expand(&[b"abc", b"def"], &mut a));
    assert!(k.expand(&[b"abcdef"], &mut b));
    assert_eq!(a, b);
}

/// A prefix of a longer output is the same bytes: the chain does not depend on
/// how much was asked for.
#[test]
fn shorter_output_is_a_prefix() {
    let k = HkdfSha512::extract(&SALT, &IKM);
    let mut long = [0u8; 128];
    let mut short = [0u8; 64];
    assert!(k.expand(&[&INFO], &mut long));
    assert!(k.expand(&[&INFO], &mut short));
    assert_eq!(&long[..64], &short[..]);
}

/// The one-byte counter bounds the output; asking past it is refused rather
/// than wrapping to a repeat of the first block.
#[test]
fn output_longer_than_the_counter_can_address_is_refused() {
    let k = HkdfSha512::extract(&SALT, &IKM);
    let mut okm = alloc::vec![0u8; 255 * 64 + 1];
    assert!(!k.expand(&[&INFO], &mut okm));
    assert!(okm.iter().all(|&b| b == 0));
}
