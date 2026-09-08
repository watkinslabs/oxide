//! Next-thread walk order, flags and handle attributes.

use super::*;

const ORDER: [u32; 4] = [7, 11, 19, 23];

#[test]
fn a_null_position_starts_at_the_first_thread() {
    assert_eq!(next_of(&ORDER, None, false), Some(7));
}

#[test]
fn a_backwards_walk_from_a_null_position_starts_at_the_last_thread() {
    assert_eq!(next_of(&ORDER, None, true), Some(23));
}

#[test]
fn each_thread_is_visited_exactly_once_in_a_full_walk() {
    let mut seen = alloc::vec::Vec::new();
    let mut position = None;
    while let Some(next) = next_of(&ORDER, position, false) {
        seen.push(next);
        position = Some(next);
        assert!(seen.len() <= ORDER.len(), "the walk must terminate");
    }
    assert_eq!(seen, ORDER.to_vec());
}

#[test]
fn a_backwards_walk_visits_the_same_threads_in_the_opposite_order() {
    let mut seen = alloc::vec::Vec::new();
    let mut position = None;
    while let Some(next) = next_of(&ORDER, position, true) {
        seen.push(next);
        position = Some(next);
        assert!(seen.len() <= ORDER.len(), "the walk must terminate");
    }
    let mut reversed = ORDER.to_vec();
    reversed.reverse();
    assert_eq!(seen, reversed);
}

#[test]
fn the_end_of_the_walk_yields_no_thread() {
    assert_eq!(next_of(&ORDER, Some(23), false), None);
    assert_eq!(next_of(&ORDER, Some(7), true), None);
    assert_eq!(next_of(&[], None, false), None);
}

#[test]
fn a_position_naming_a_departed_thread_resumes_where_it_would_have_been() {
    // 13 is not in the process; the walk continues from that point rather
    // than restarting, so a caller holding a handle to an exited thread does
    // not re-enumerate the ones it already saw.
    assert_eq!(next_of(&ORDER, Some(13), false), Some(19));
    assert_eq!(next_of(&ORDER, Some(13), true), Some(11));
}

#[test]
fn only_the_reverse_flag_is_defined() {
    assert!(flags_admitted(0));
    assert!(flags_admitted(NEXT_THREAD_PREVIOUS));
    assert!(!flags_admitted(2));
    assert!(!flags_admitted(u32::MAX));
    assert!(!walks_backwards(0));
    assert!(walks_backwards(NEXT_THREAD_PREVIOUS));
}

#[test]
fn an_undefined_attribute_bit_is_refused() {
    assert!(attributes_admitted(0));
    assert!(attributes_admitted(OBJ_INHERIT));
    assert!(attributes_admitted(OBJ_VALID_ATTRIBUTES));
    assert!(!attributes_admitted(0x0000_0004));
    assert!(!attributes_admitted(0x8000_0000));
}

#[test]
fn only_inheritance_becomes_a_handle_flag() {
    // The attribute word and the handle flag are different numbering: the
    // inherit attribute is bit one, the handle flag is bit zero.
    assert_eq!(handle_flags_from_attributes(OBJ_INHERIT), HANDLE_FLAG_INHERIT);
    assert_eq!(OBJ_INHERIT, 0x2);
    assert_eq!(HANDLE_FLAG_INHERIT, 0x1);
    assert_eq!(handle_flags_from_attributes(0), 0);
    // A name-lookup attribute describes a lookup this service never does.
    assert_eq!(handle_flags_from_attributes(0x0000_0040), 0);
}
