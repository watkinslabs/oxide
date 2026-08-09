use crate::ldt_abi::read::{plan_read, plan_read_default};
use crate::ldt_abi::{DEFAULT_LDT_BYTES, LDT_TABLE_BYTES};

#[test]
fn a_process_with_no_ldt_reads_back_nothing() {
    // Not a zero-filled buffer and not the requested count: a literal zero,
    // with the caller's buffer untouched. That is the only signal that
    // distinguishes "no table" from "a table of zero descriptors".
    let p = plan_read(0, 4096);
    assert_eq!((p.copy, p.zero), (0, 0));
    assert_eq!(p.retval(), 0);
}

#[test]
fn a_short_request_is_truncated_not_padded() {
    let p = plan_read(8, 16);
    assert_eq!((p.copy, p.zero), (16, 0));
    assert_eq!(p.retval(), 16);
}

#[test]
fn a_long_request_is_zero_filled_to_the_requested_count() {
    let p = plan_read(2, 64);
    assert_eq!((p.copy, p.zero), (16, 48));
    assert_eq!(p.retval(), 64, "the caller is told the whole buffer was written");
}

#[test]
fn the_request_is_clamped_to_the_whole_table() {
    assert_eq!(LDT_TABLE_BYTES, 8192 * 8);
    let p = plan_read(1, u64::MAX);
    assert_eq!(p.retval(), LDT_TABLE_BYTES as i64);
    assert_eq!((p.copy, p.zero), (8, LDT_TABLE_BYTES - 8));
    // Clamping is what keeps the return value inside the `int` the ABI hands
    // back: an unclamped count would be truncated on the way out.
    assert!(p.retval() <= i32::MAX as i64);
}

#[test]
fn a_full_table_read_copies_everything_and_pads_nothing() {
    let p = plan_read(8192, LDT_TABLE_BYTES);
    assert_eq!((p.copy, p.zero), (LDT_TABLE_BYTES, 0));
}

#[test]
fn a_zero_byte_request_copies_nothing() {
    assert_eq!(plan_read(4, 0).retval(), 0);
    assert_eq!(plan_read_default(0).retval(), 0);
}

#[test]
fn the_default_ldt_is_a_fixed_run_of_zeroes() {
    assert_eq!(DEFAULT_LDT_BYTES, 128);
    let p = plan_read_default(4096);
    assert_eq!((p.copy, p.zero), (0, DEFAULT_LDT_BYTES));
    assert_eq!(p.retval(), DEFAULT_LDT_BYTES as i64);
    let p = plan_read_default(40);
    assert_eq!((p.copy, p.zero), (0, 40));
    // Nothing is ever copied from the live table for this sub-function.
    assert_eq!(plan_read_default(u64::MAX).copy, 0);
}
