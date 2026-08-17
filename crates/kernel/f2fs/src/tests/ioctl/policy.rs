//! The encryption policy as the ioctl carries it.
//!
//! Two forms of one thing meet here and they differ in BOTH length and field
//! order. The tests that matter are the ones that would pass if the stored
//! form were used by mistake: the stored form's first byte is a context
//! version, the wire form's is a policy version, and the two numbering
//! schemes disagree.

use alloc::vec;
use crate::crypto::policy::{KeyId, Policy};
use crate::crypto::uapi::{POLICY_V1, POLICY_V2};
use crate::ioctl::policy::*;
use crate::ioctl::uapi::{POLICY_V1_SIZE, POLICY_V2_SIZE};

fn v1() -> Policy {
    Policy {
        version: POLICY_V1, contents_mode: 1, filenames_mode: 4, flags: 2,
        log2_data_unit_size: 0, key: KeyId::Descriptor([1, 2, 3, 4, 5, 6, 7, 8]),
    }
}

fn v2() -> Policy {
    Policy {
        version: POLICY_V2, contents_mode: 1, filenames_mode: 4, flags: 0,
        log2_data_unit_size: 12, key: KeyId::Identifier([0xaa; 16]),
    }
}

#[test]
fn each_version_round_trips_through_the_wire_form() {
    for p in [v1(), v2()] {
        assert_eq!(parse_wire(&encode_wire(&p)), Ok(p));
    }
}

/// The two versions are different LENGTHS, and the length is what a caller
/// supplies. Encoding one at the other's length would read a neighbour's
/// bytes as part of the key.
#[test]
fn the_two_versions_occupy_their_own_lengths() {
    assert_eq!(wire_len(&v1()), POLICY_V1_SIZE as usize);
    assert_eq!(wire_len(&v2()), POLICY_V2_SIZE as usize);
    assert_eq!(encode_wire(&v1()).len(), POLICY_V1_SIZE as usize);
    assert_eq!(encode_wire(&v2()).len(), POLICY_V2_SIZE as usize);
}

/// The older form is accepted from a buffer that only holds the older form.
/// Requiring the newer length would refuse every caller still sending it.
#[test]
fn the_older_form_parses_from_a_buffer_only_long_enough_for_it() {
    let b = encode_wire(&v1());
    assert_eq!(b.len(), POLICY_V1_SIZE as usize);
    assert_eq!(parse_wire(&b), Ok(v1()));
}

#[test]
fn a_buffer_too_short_for_the_version_it_names_is_refused() {
    let mut b = encode_wire(&v2());
    b.truncate(POLICY_V1_SIZE as usize);
    assert!(parse_wire(&b).is_err());
    assert!(parse_wire(&[]).is_err());
}

#[test]
fn a_version_this_build_does_not_know_is_refused() {
    let mut b = vec![0u8; POLICY_V2_SIZE as usize];
    b[0] = 9;
    assert!(parse_wire(&b).is_err());
}

/// The newer form's three reserved bytes must be zero, or a later field
/// defined there would arrive already set.
#[test]
fn the_newer_forms_reserved_bytes_must_be_zero() {
    let mut b = encode_wire(&v2());
    b[5] = 1;
    assert!(parse_wire(&b).is_err());
}

/// The newer form spends the word after the head on a data-unit shift; the
/// older form spends it on the first four bytes of the key name. Reading one
/// as the other names a different key.
#[test]
fn the_word_after_the_head_means_different_things_in_the_two_versions() {
    let a = encode_wire(&v1());
    let b = encode_wire(&v2());
    // In the older form that byte is part of the chosen name.
    assert_eq!(a[4], 1);
    // In the newer form it is the shift.
    assert_eq!(b[4], 12);
    assert_eq!(parse_wire(&b).unwrap().log2_data_unit_size, 12);
    assert_eq!(parse_wire(&a).unwrap().log2_data_unit_size, 0);
}

/// The older query has no room for the newer form, and truncating one would
/// hand back a policy naming a key that does not exist. It refuses instead.
#[test]
fn the_older_query_refuses_to_truncate_a_newer_policy() {
    assert_eq!(encode_v1(&v1()), Some(encode_wire(&v1())));
    assert_eq!(encode_v1(&v2()), None);
}

/// The stored form and the wire form are NOT interchangeable: parsing one as
/// the other must not succeed by accident. The stored form's first byte is a
/// context version, whose value for the newer scheme happens to equal the
/// wire form's — so the length is what separates them here.
#[test]
fn the_stored_form_is_not_the_wire_form() {
    let ctx = crate::crypto::policy::Context { policy: v1(), nonce: [3; 16] };
    let (stored, used) = crate::crypto::policy::serialize(&ctx);
    let wire = encode_wire(&v1());
    assert_ne!(&stored[..used], &wire[..]);
    // The stored form is longer, because it carries the file's own nonce.
    assert!(used > wire.len());
}
