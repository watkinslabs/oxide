//! Positions and widths each service declares, against a caller whose frame
//! words carry a stale upper half and whose booleans are one byte.

use super::*;

/// A frame word whose low half is the caller's value and whose upper half is
/// whatever the frame held before the 32-bit store.
const fn stale(value: u32) -> u64 { 0x7fff_dead_0000_0000 | value as u64 }

#[test]
fn a_ulong_is_the_low_half_of_its_word() {
    assert_eq!(ulong(stale(0x1000)), 0x1000);
    assert_eq!(ulong(u64::MAX), u32::MAX);
    assert_eq!(ulong(0), 0);
}

#[test]
fn a_long_keeps_its_sign_within_thirty_two_bits() {
    assert_eq!(long(stale(0x7fff_ffff)), i32::MAX);
    assert_eq!(long(stale(u32::MAX)), -1);
    assert_eq!(long(1), 1);
}

#[test]
fn a_boolean_is_one_byte_and_any_nonzero_value_is_true() {
    assert!(!boolean(0));
    assert!(!boolean(0x7fff_dead_0000_0000));
    assert!(boolean(1));
    assert!(boolean(2));
    assert!(boolean(0xffff_ff00_0000_0001));
}

#[test]
fn a_handle_keeps_its_pseudo_handle_values() {
    assert_eq!(handle(u64::MAX), u32::MAX);
    assert_eq!(handle(u64::MAX - 1), u32::MAX - 1);
    assert_eq!(handle(0x1c), 0x1c);
}

#[test]
fn set_timer_reads_a_due_time_pointer_a_period_and_a_resume_flag() {
    let call = set_timer([0x1c, 0x7fff_0000_1000, 0, 0, stale(0), stale(5000), 0x7fff_0000_2000]);
    assert_eq!(call.handle, 0x1c);
    assert_eq!(call.when, 0x7fff_0000_1000);
    assert_eq!(call.period, 5000);
    assert!(!call.resume);
    assert_eq!(call.state, 0x7fff_0000_2000);
}

#[test]
fn set_timer_period_is_not_the_apc_argument() {
    // The third and fourth arguments are the APC routine and its argument;
    // the period is the sixth. Reading the period from the third refused
    // every timer a caller armed with a callback.
    let call = set_timer([1, 0x7fff_0000_1000, 0x1_4000_0000, 0xdead, 1, 100, 0]);
    assert_eq!(call.callback, 0x1_4000_0000);
    assert_eq!(call.argument, 0xdead);
    assert_eq!(call.period, 100);
    assert!(call.resume);
}

#[test]
fn set_io_completion_takes_five_scalar_arguments() {
    let call = set_io_completion([0x20, 0xdead_beef_0000, 0x7fff_0000_0100, stale(0xc000_000d), 0x40]);
    assert_eq!(call.handle, 0x20);
    assert_eq!(call.key, 0xdead_beef_0000);
    assert_eq!(call.value, 0x7fff_0000_0100);
    assert_eq!(call.status, 0xc000_000d);
    assert_eq!(call.information, 0x40);
}

#[test]
fn remove_io_completion_takes_four_output_pointers() {
    let call = remove_io_completion([0x20, 0x7fff_1000, 0x7fff_1008, 0x7fff_1010, 0]);
    assert_eq!((call.handle, call.key, call.value, call.io, call.timeout),
        (0x20, 0x7fff_1000, 0x7fff_1008, 0x7fff_1010, 0));
}

#[test]
fn remove_io_completion_ex_narrows_its_count_and_reads_one_alertable_byte() {
    let call = remove_io_completion_ex([0x20, 0x7fff_1000, stale(8), 0x7fff_2000, 0, stale(0)]);
    assert_eq!(call.count, 8);
    assert!(!call.alertable);
    assert!(remove_io_completion_ex([0, 0, 1, 0, 0, 1]).alertable);
}

#[test]
fn duplicate_object_takes_seven_arguments_with_three_narrow_ones() {
    let call = duplicate_object([u64::MAX, 0x1c, u64::MAX, 0x7fff_3000, stale(0x1f_0003), stale(0), stale(2)]);
    assert_eq!(call.source_process, u64::MAX);
    assert_eq!(call.source, 0x1c);
    assert_eq!(call.target, 0x7fff_3000);
    assert_eq!(call.access, 0x1f_0003);
    assert_eq!(call.attributes, 0);
    assert_eq!(call.options, 2);
}

#[test]
fn create_semaphore_counts_are_signed_and_thirty_two_bits() {
    let call = create_semaphore([0x7fff_4000, stale(0x1f_0003), 0, stale(0), stale(1)]);
    assert_eq!((call.initial, call.maximum), (0, 1));
    assert_eq!(call.access, 0x1f_0003);
    assert_eq!(create_semaphore([0, 0, 0, 0, stale(u32::MAX)]).maximum, -1);
}

#[test]
fn query_information_atom_takes_a_sixteen_bit_atom() {
    let call = query_information_atom([0xc001, stale(0), 0x7fff_5000, stale(24), 0x7fff_5100]);
    assert_eq!(call.atom, 0xc001);
    assert_eq!(call.size, 24);
    assert_eq!(call.return_size, 0x7fff_5100);
}

#[test]
fn notify_change_key_reads_its_four_frame_words_at_their_own_widths() {
    let call = notify_change_key([0x1c, 0x20, 0, 0, 0x7fff_6000, stale(4), stale(0), 0, stale(0), stale(1)]);
    assert_eq!(call.filter, 4);
    assert_eq!(call.length, 0);
    assert!(!call.subtree);
    assert!(call.asynchronous);
    assert_eq!(call.io, 0x7fff_6000);
}

#[test]
fn notify_change_key_reads_a_true_boolean_from_a_word_whose_low_byte_is_zero_as_false() {
    // A frame word left holding 0x...00 is FALSE however large the word is.
    let call = notify_change_key([0, 0, 0, 0, 1, 4, 0x7fff_dead_0000_0100, 0, 0, 1]);
    assert!(!call.subtree);
    assert!(notify_change_key([0, 0, 0, 0, 1, 4, 1, 0, 0, 1]).subtree);
}
