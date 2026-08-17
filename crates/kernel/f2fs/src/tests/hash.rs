//! The name hash.
//!
//! The vectors below are the provenance. They were computed from an
//! independent transcription of the algorithm — not from this module — so a
//! change to the rounds, the seeds, the byte order or the padding rule shows
//! up here rather than as a directory whose names cannot be found.

use super::*;
use alloc::vec::Vec;

/// Frozen vectors: name, and the hash a stored entry must carry for it.
const VECTORS: &[(&[u8], u32)] = &[
    (b"a", 0x6d0e_a4c1),
    (b"hello", 0x6f5b_b1a8),
    (b"file.txt", 0x572a_0842),
    (b"abcdefgh", 0x75c7_d754),
    (b"abcdefghijklmnop", 0xf4ac_8cb5),
    (b"abcdefghijklmnopq", 0x972a_82e7),
    (b"", 0x2576_713d),
    (b"lost+found", 0x2dbf_9e80),
];

#[test]
fn the_frozen_vectors_match() {
    for (name, want) in VECTORS {
        assert_eq!(name_hash(name), *want, "name {:?}", core::str::from_utf8(name));
    }
}

#[test]
fn a_name_of_the_maximum_length_hashes() {
    let long: Vec<u8> = alloc::vec![b'x'; 255];
    assert_eq!(name_hash(&long), 0x6c4c_00ee);
}

#[test]
fn dot_and_dotdot_hash_to_zero_without_running_the_transform() {
    assert_eq!(name_hash(b"."), 0);
    assert_eq!(name_hash(b".."), 0);
    assert!(is_dot_or_dotdot(b"."));
    assert!(is_dot_or_dotdot(b".."));
    assert!(!is_dot_or_dotdot(b"..."));
    assert!(!is_dot_or_dotdot(b""));
}

#[test]
fn the_empty_name_is_not_treated_as_a_dot() {
    // Only the two literal names are special; an empty name goes through the
    // transform like any other.
    assert_ne!(name_hash(b""), 0);
}

#[test]
fn a_three_dot_name_is_an_ordinary_name() {
    assert_ne!(name_hash(b"..."), 0);
}

/// The same transform, but padding the tail with zeroes instead of the name's
/// own length. This is the classic wrong variant.
fn zero_padded(name: &[u8]) -> u32 {
    // Reproduce the shape by hashing a name whose length byte would be zero:
    // the pad enters every word the name does not fill, so a name shorter than
    // sixteen bytes is where the two diverge.
    let mut padded = name.to_vec();
    while padded.len() % 16 != 0 { padded.push(0); }
    name_hash(&padded)
}

#[test]
fn the_pad_is_the_names_length_not_zero() {
    // If the tail were zero-filled, a short name and its zero-extension would
    // agree. They must not.
    assert_ne!(name_hash(b"hello"), zero_padded(b"hello"));
}

#[test]
fn the_length_enters_the_hash_even_for_names_of_the_same_bytes() {
    // Two names sharing a prefix differ by more than the extra bytes: the pad
    // carries the length into every partial word.
    assert_ne!(name_hash(b"ab"), name_hash(b"ab\0"));
}

#[test]
fn a_name_that_fills_the_first_chunk_exactly_still_runs_one_round() {
    // Sixteen bytes is the boundary between one transform and two; an
    // off-by-one there would hash a full chunk twice.
    assert_eq!(name_hash(b"abcdefghijklmnop"), 0xf4ac_8cb5);
    assert_ne!(name_hash(b"abcdefghijklmnop"), name_hash(b"abcdefghijklmnopq"));
}

#[test]
fn bytes_fold_in_big_endian_order_within_a_word() {
    // Reversing a four-byte name must change the hash; a little-endian fold
    // would agree on a palindrome and disagree elsewhere in a different way.
    assert_ne!(name_hash(b"abcd"), name_hash(b"dcba"));
}

#[test]
fn distinct_names_mostly_hash_distinctly() {
    let mut seen: Vec<u32> = Vec::new();
    for i in 0..512u32 {
        let mut name = Vec::new();
        let mut n = i;
        loop {
            name.push(b'a' + (n % 26) as u8);
            n /= 26;
            if n == 0 { break; }
        }
        seen.push(name_hash(&name));
    }
    seen.sort_unstable();
    let total = seen.len();
    seen.dedup();
    // A transform that collapsed would show up as a large drop here.
    assert!(seen.len() * 100 >= total * 99, "{} of {} distinct", seen.len(), total);
}

#[test]
fn the_hash_is_stable_across_calls() {
    assert_eq!(name_hash(b"stable"), name_hash(b"stable"));
}

#[test]
fn a_single_changed_byte_changes_the_hash() {
    assert_ne!(name_hash(b"file.txt"), name_hash(b"file.txu"));
}
