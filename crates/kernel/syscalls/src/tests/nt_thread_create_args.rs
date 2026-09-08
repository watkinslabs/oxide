//! Thread creation reads eleven arguments at their declared positions.

use super::*;

const REGISTERS: [u64; 6] = [0x1000, 0x001f_03ff, 0x2000, 0xffff_ffff_ffff_ffff, 0x3000, 0x4000];
const FRAME: [u64; 5] = [1, 0, 0x1_0000, 0x10_0000, 0x5000];

#[test]
fn every_argument_is_read_at_its_declared_position() {
    let a = args(REGISTERS, FRAME);
    assert_eq!(a.handle, 0x1000);
    assert_eq!(a.desired_access, 0x001f_03ff);
    assert_eq!(a.attributes, 0x2000);
    assert_eq!(a.process, u64::MAX);
    assert_eq!(a.start, 0x3000);
    assert_eq!(a.parameter, 0x4000);
    assert_eq!(a.flags, 1);
    assert_eq!(a.zero_bits, 0);
    assert_eq!(a.stack_commit, 0x1_0000);
    assert_eq!(a.stack_reserve, 0x10_0000);
    assert_eq!(a.attribute_list, 0x5000);
}

#[test]
fn the_start_routine_is_not_the_argument_that_precedes_it() {
    // Reading only six words made the fifth argument the stack size and the
    // fourth the start routine; both are two positions from where they are
    // declared.
    let a = args(REGISTERS, FRAME);
    assert_ne!(a.start, REGISTERS[2]);
    assert_eq!(a.start, REGISTERS[4]);
    assert_eq!(a.process, REGISTERS[3]);
}

#[test]
fn the_flags_word_is_the_low_half_of_its_frame_slot() {
    let a = args(REGISTERS, [0x7fff_dead_0000_0001, 0, 0, 0, 0]);
    assert_eq!(a.flags, 1);
    assert!(starts_suspended(a.flags));
}

#[test]
fn the_access_mask_is_the_low_half_of_its_slot() {
    let a = args([0, 0x1234_5678_001f_03ff, 0, 0, 0, 0], FRAME);
    assert_eq!(a.desired_access, 0x001f_03ff);
}

#[test]
fn the_stack_sizes_keep_their_whole_slots() {
    let a = args(REGISTERS, [0, 0, 0x1_0000_0000, 0x2_0000_0000, 0]);
    assert_eq!(a.stack_commit, 0x1_0000_0000);
    assert_eq!(a.stack_reserve, 0x2_0000_0000);
}

#[test]
fn flags_this_kernel_does_not_act_on_are_not_a_refusal() {
    let asked = THREAD_CREATE_FLAGS_CREATE_SUSPENDED | THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH
        | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER | THREAD_CREATE_FLAGS_SKIP_LOADER_INIT
        | THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE;
    assert!(starts_suspended(asked));
    assert!(!starts_suspended(asked & !THREAD_CREATE_FLAGS_CREATE_SUSPENDED));
}

#[test]
fn a_reservation_wider_than_an_address_but_short_of_a_mask_is_refused() {
    assert!(!zero_bits_refused(0));
    assert!(!zero_bits_refused(21));
    assert!(zero_bits_refused(22));
    assert!(zero_bits_refused(31));
    assert!(!zero_bits_refused(32));
    assert!(!zero_bits_refused(0x7fff_ffff_0000));
}
