// Hosted tests for the pure temp-name value layer. These pin the property the
// clock-seeded predecessor lacked: the suffix is a deterministic function of
// the getrandom(2) bytes and of nothing else. A "two names differ" test does
// NOT pin that — a clock-derived name also differs between calls.
use super::value::{
    bytes_needed, fill_suffix, mix_random_values, needs_redraw, DigitPool, BASE, BASE_62_DIGITS,
    BASE_62_POWER, BIASED_MIN, LETTERS, RANDOM_VALUE_BYTES, X_SUFFIX_LEN,
};
use std::collections::HashSet;
use std::string::String;
use std::vec::Vec;

fn suffix(bytes: &[u8], n: usize) -> String {
    let mut out = std::vec![0u8; n];
    assert!(fill_suffix(bytes, &mut out), "fill_suffix rejected {} bytes for {n} letters", bytes.len());
    String::from_utf8(out).unwrap()
}

// glibc letters[]: 62 distinct [A-Za-z0-9] chars, lowercase then uppercase
// then digits (the order fixes every expected vector below).
#[test]
fn alphabet_matches_glibc_letters() {
    assert_eq!(LETTERS.len(), BASE);
    assert_eq!(BASE, 62);
    assert!(LETTERS.iter().all(|c| c.is_ascii_alphanumeric()));
    assert_eq!(LETTERS.iter().copied().collect::<HashSet<u8>>().len(), BASE);
    assert_eq!(&LETTERS[..3], b"abc");
    assert_eq!(&LETTERS[26..29], b"ABC");
    assert_eq!(&LETTERS[52..], b"0123456789");
}

// Fixed vectors: exact bytes → exact suffix. Computed from glibc's
// `XXXXXX[i] = letters[vdigbuf % 62]; vdigbuf /= 62` over the little-endian
// random_value, so any change to alphabet order or digit order fails here.
#[test]
fn fixed_vectors_pin_the_mapping() {
    assert_eq!(suffix(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef], X_SUFFIX_LEN), "LqhAzj");
    assert_eq!(suffix(&[0u8; 8], X_SUFFIX_LEN), "aaaaaa");
    assert_eq!(suffix(&[0xffu8; 8], X_SUFFIX_LEN), "pIrkgb");
    // Two draws: the 11th letter starts the second random_value.
    let two: Vec<u8> = (1u8..=16).collect();
    assert_eq!(suffix(&two, 11), "9SZQQaIpTQz");
}

// The suffix depends on the input bytes and on nothing else: same bytes in,
// same letters out, every time. A clock-mixed generator fails this.
#[test]
fn suffix_is_a_pure_function_of_its_bytes() {
    let b = [0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78];
    let first = suffix(&b, X_SUFFIX_LEN);
    for _ in 0..1000 { assert_eq!(suffix(&b, X_SUFFIX_LEN), first); }
    // Distinct entropy still yields a distinct name (injective below 62**6).
    let mut c = b;
    c[0] ^= 1;
    assert_ne!(suffix(&c, X_SUFFIX_LEN), first);
}

// Every byte value must land inside [A-Za-z0-9]: catches an out-of-range
// alphabet index or a sign-extension bug in the modulo.
#[test]
fn every_input_byte_yields_alphabet_chars() {
    for v in 0u8..=255 {
        for pos in 0..RANDOM_VALUE_BYTES {
            let mut b = [0u8; RANDOM_VALUE_BYTES];
            b[pos] = v;
            for c in suffix(&b, X_SUFFIX_LEN).bytes() {
                assert!(c.is_ascii_alphanumeric(), "byte {v} at {pos} produced {c:#x}");
                assert!(LETTERS.contains(&c));
            }
        }
    }
}

// A run of consecutive values walks the alphabet evenly in the low digit —
// the mapping is a plain base-62 expansion, not a skewed one.
#[test]
fn low_digit_is_uniform_over_consecutive_values() {
    let mut hist = [0u32; BASE];
    let reps = 100u64;
    for v in 0..(BASE as u64) * reps {
        let s = suffix(&v.to_le_bytes(), X_SUFFIX_LEN);
        let idx = LETTERS.iter().position(|c| *c == s.as_bytes()[0]).unwrap();
        hist[idx] += 1;
    }
    assert!(hist.iter().all(|n| *n as u64 == reps));
}

// Byte budget: 6 letters need exactly one 8-byte draw; 11 need two.
#[test]
fn byte_budget_matches_base62_digits() {
    assert_eq!(BASE_62_DIGITS, 10);
    assert_eq!(RANDOM_VALUE_BYTES, 8);
    assert_eq!(bytes_needed(X_SUFFIX_LEN), RANDOM_VALUE_BYTES);
    assert_eq!(bytes_needed(BASE_62_DIGITS as usize), RANDOM_VALUE_BYTES);
    assert_eq!(bytes_needed(BASE_62_DIGITS as usize + 1), 2 * RANDOM_VALUE_BYTES);
    // Short entropy is rejected, never silently padded.
    let mut out = [0u8; X_SUFFIX_LEN];
    assert!(!fill_suffix(&[0u8; RANDOM_VALUE_BYTES - 1], &mut out));
    assert!(fill_suffix(&[0u8; RANDOM_VALUE_BYTES], &mut out));
}

// One draw yields exactly BASE_62_DIGITS letters before the pool asks again.
#[test]
fn digit_pool_holds_ten_letters_per_draw() {
    let mut p = DigitPool::new();
    assert!(p.is_empty());
    p.refill(u64::MAX);
    for _ in 0..BASE_62_DIGITS { assert!(!p.is_empty()); p.next_letter(); }
    assert!(p.is_empty());
}

// glibc bias rejection: redraw high-quality values ≥ biased_min only.
#[test]
fn bias_rejection_matches_glibc() {
    assert_eq!(BIASED_MIN, u64::MAX - u64::MAX % BASE_62_POWER);
    assert_eq!(BIASED_MIN % BASE_62_POWER, 0);
    assert!(needs_redraw(true, BIASED_MIN));
    assert!(needs_redraw(true, u64::MAX));
    assert!(!needs_redraw(true, BIASED_MIN - 1));
    // Ersatz values are biased anyway; glibc accepts them rather than looping.
    assert!(!needs_redraw(false, u64::MAX));
}

// glibc mix_random_values(r, s) = 2862933555777941757*r + 3037000493 ^ s.
#[test]
fn ersatz_mixer_matches_glibc() {
    assert_eq!(mix_random_values(1, 2), 2_862_933_558_814_942_248);
    assert_eq!(mix_random_values(0xdead_beef, 0x1234), 11_530_567_245_777_266_516);
    assert_eq!(mix_random_values(0, 0), 3_037_000_493);
}
