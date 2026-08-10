use super::*;
use super::super::ops::{IORING_OP_NOP, IORING_OP_NOP128, IORING_OP_URING_CMD128};

const MIXED: u32 = IORING_SETUP_SQE_MIXED;
const WIDE: u32 = IORING_SETUP_SQE128;

#[test]
fn a_wide_ring_strides_at_128_and_every_other_ring_at_64() {
    assert_eq!(slot_size(0), 64);
    assert_eq!(slot_size(MIXED), 64, "mixed keeps the 64-byte stride");
    assert_eq!(slot_size(WIDE), 128);
}

#[test]
fn the_offset_is_the_index_times_the_stride() {
    assert_eq!(sqe_offset(64, 0), 0);
    assert_eq!(sqe_offset(64, 3), 192);
    assert_eq!(sqe_offset(128, 3), 384);
    // The last slot of a 32-entry wide array ends exactly at the array's end.
    assert_eq!(sqe_offset(128, 31) + 128, 32 * 128);
}

#[test]
fn only_the_wide_opcodes_are_128_bytes() {
    assert!(op_is_128(IORING_OP_NOP128));
    assert!(op_is_128(IORING_OP_URING_CMD128));
    assert!(!op_is_128(IORING_OP_NOP));
    for op in 0u8..63 { assert!(!op_is_128(op), "op {op}"); }
}

/// A 64-byte operation costs one slot on every ring shape, wide included: a
/// wide ring simply leaves the second half of the slot unread.
#[test]
fn a_narrow_operation_costs_one_slot_on_every_ring() {
    for flags in [0, MIXED, WIDE] {
        assert_eq!(extra_slots(flags, IORING_OP_NOP, 0, 8, 8), Ok(0), "flags {flags:#x}");
        assert_eq!(extra_slots(flags, IORING_OP_NOP, 7, 8, 1), Ok(0),
                   "the last slot, with one entry left, is still fine for a narrow op");
    }
}

/// The refusal that makes the flags mean something: a 128-byte operation on a
/// ring that carries only 64-byte entries has nowhere for its second half.
#[test]
fn a_wide_operation_on_a_narrow_ring_is_einval() {
    assert_eq!(extra_slots(0, IORING_OP_NOP128, 0, 8, 8), Err(Errno::Einval));
    assert_eq!(extra_slots(0, IORING_OP_URING_CMD128, 0, 8, 8), Err(Errno::Einval));
    assert!(!carries_128(0));
}

#[test]
fn a_wide_operation_on_a_wide_ring_costs_one_slot() {
    assert!(carries_128(WIDE));
    assert_eq!(extra_slots(WIDE, IORING_OP_NOP128, 0, 8, 1), Ok(0));
    // Even in the array's last slot: the whole 128 bytes are in that slot.
    assert_eq!(extra_slots(WIDE, IORING_OP_NOP128, 7, 8, 1), Ok(0));
}

#[test]
fn a_wide_operation_on_a_mixed_ring_costs_two_slots() {
    assert!(carries_128(MIXED));
    assert_eq!(extra_slots(MIXED, IORING_OP_NOP128, 0, 8, 2), Ok(1));
    assert_eq!(extra_slots(MIXED, IORING_OP_NOP128, 6, 8, 8), Ok(1));
}

/// The two ways a mixed ring refuses a wide entry, each of which would
/// otherwise have the kernel read 64 bytes of the command from a slot the
/// submitter meant for something else.
#[test]
fn a_mixed_wide_entry_needs_two_entries_and_must_not_wrap() {
    // Only one entry left in the batch: the second half was never published.
    assert_eq!(extra_slots(MIXED, IORING_OP_NOP128, 0, 8, 1), Err(Errno::Einval));
    // The array's last slot: the second half would wrap to slot zero.
    assert_eq!(extra_slots(MIXED, IORING_OP_NOP128, 7, 8, 8), Err(Errno::Einval));
    // One before the last is the deepest placement that works.
    assert_eq!(extra_slots(MIXED, IORING_OP_NOP128, 6, 8, 2), Ok(1));
}

/// A two-entry mixed ring is the shallowest one that can hold a wide entry at
/// all, and only in its first slot — which is why setup refuses a shallower
/// one outright.
#[test]
fn the_shallowest_mixed_ring_places_a_wide_entry_only_at_slot_zero() {
    assert_eq!(extra_slots(MIXED, IORING_OP_NOP128, 0, 2, 2), Ok(1));
    assert_eq!(extra_slots(MIXED, IORING_OP_NOP128, 1, 2, 2), Err(Errno::Einval));
}
