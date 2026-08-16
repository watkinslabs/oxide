//! The metadata-only marker, as bytes.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::limits::{METACOPY_MAX_SIZE, METACOPY_MIN_SIZE};

use super::{decode, recorded_size, Metacopy};

#[test]
fn an_empty_marker_is_written_as_nothing() {
    // An older kernel checks only that the attribute EXISTS. A header written
    // where it expects nothing is still readable, but the zero-length form is
    // what has always been on disk, so that is what is written.
    assert!(Metacopy::empty().encode().is_empty());
    assert_eq!(decode(&[]), Ok(Metacopy::empty()));
}

#[test]
fn a_marker_with_a_digest_round_trips() {
    let m = Metacopy { version: 0, flags: 0, digest_algo: 1, digest: vec![0xab; 32] };
    let raw = m.encode();
    assert_eq!(raw.len(), METACOPY_MIN_SIZE + 32);
    assert_eq!(raw[1] as usize, raw.len());
    assert_eq!(decode(&raw), Ok(m));
}

#[test]
fn a_digest_is_recognised_only_with_an_algorithm() {
    assert!(!Metacopy::empty().has_digest());
    assert!(!Metacopy { digest: vec![1], ..Metacopy::empty() }.has_digest());
    assert!(Metacopy { digest_algo: 1, digest: vec![1], ..Metacopy::empty() }.has_digest());
}

#[test]
fn a_truncated_record_is_an_io_error() {
    assert_eq!(decode(&[0, 3, 0]), Err(Errno::Eio));
}

#[test]
fn a_length_byte_disagreeing_with_the_value_is_an_io_error() {
    // Trusting it would read the digest from the wrong bytes, which either
    // rejects good data or accepts bad.
    assert_eq!(decode(&[0, 8, 0, 1]), Err(Errno::Eio));
}

#[test]
fn an_unknown_version_is_an_io_error() {
    assert_eq!(decode(&[1, 4, 0, 0]), Err(Errno::Eio));
}

#[test]
fn a_record_wider_than_the_widest_digest_is_refused() {
    let raw: Vec<u8> = core::iter::once(0)
        .chain(core::iter::once((METACOPY_MAX_SIZE + 1) as u8))
        .chain(core::iter::repeat(0).take(METACOPY_MAX_SIZE - 1))
        .collect();
    assert_eq!(decode(&raw), Err(Errno::Eio));
}

#[test]
fn a_zero_length_value_still_counts_as_a_marker() {
    // Absence and emptiness are different answers: absent means the object has
    // its own data, empty means the data is below with nothing recorded.
    assert_eq!(recorded_size(None), 0);
    assert_eq!(recorded_size(Some(&[])), METACOPY_MIN_SIZE);
    assert_eq!(recorded_size(Some(&[0, 5, 0, 0, 9])), 5);
}
