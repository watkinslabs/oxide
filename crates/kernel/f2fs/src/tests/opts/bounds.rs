//! Values that describe a layout are refused outside their range, and refused
//! at FULL WIDTH — a value that only fits after narrowing is a different value.

use syscall::errno::Errno;

use crate::opts::bounds::{MAX_INLINE_XATTR, MIN_INLINE_XATTR};
use crate::opts::{parse, Options};

fn p(s: &str) -> Result<Options, Errno> { parse(Options::defaults(), s) }

#[test]
fn a_log_count_is_checked_before_it_is_narrowed() {
    // Two hundred and fifty-eight is not two. Narrowing first would mount a
    // volume with two logs for a line that asked for something impossible.
    assert_eq!(p("active_logs=258"), Err(Errno::Einval));
    assert_eq!(p("active_logs=262"), Err(Errno::Einval));
    assert_eq!(p("active_logs=6").unwrap().active_logs, 6);
}

#[test]
fn only_the_three_log_counts_the_checkpoint_has_slots_for_are_taken() {
    for n in [2u32, 4, 6] {
        assert_eq!(p(&alloc::format!("active_logs={n}")).unwrap().active_logs, n as u8);
    }
    for n in [0u32, 1, 3, 5, 7, 8] {
        assert_eq!(p(&alloc::format!("active_logs={n}")), Err(Errno::Einval), "{n}");
    }
}

#[test]
fn an_inline_attribute_reservation_below_its_own_header_is_refused() {
    assert_eq!(p(&alloc::format!("inline_xattr_size={}", MIN_INLINE_XATTR - 1)),
               Err(Errno::Einval));
    assert!(p(&alloc::format!("inline_xattr_size={MIN_INLINE_XATTR}")).is_ok());
}

#[test]
fn an_inline_attribute_reservation_past_the_address_array_is_refused() {
    assert!(p(&alloc::format!("inline_xattr_size={MAX_INLINE_XATTR}")).is_ok());
    assert_eq!(p(&alloc::format!("inline_xattr_size={}", MAX_INLINE_XATTR + 1)),
               Err(Errno::Einval));
}

#[test]
fn an_inline_attribute_reservation_is_checked_before_it_is_narrowed() {
    // Sixty-five thousand five hundred and thirty-six narrows to zero. A
    // reservation of zero is a volume whose inline attributes silently vanish.
    assert_eq!(p("inline_xattr_size=65536"), Err(Errno::Einval));
    assert_eq!(p("inline_xattr_size=65576"), Err(Errno::Einval));
}

#[test]
fn the_reservation_range_is_the_one_the_layout_leaves() {
    // Both ends come from the layout, not from a number someone picked: the
    // header the region must hold, and what is left of the address array.
    assert_eq!(MIN_INLINE_XATTR, 6);
    assert!(MAX_INLINE_XATTR > MIN_INLINE_XATTR);
    assert!(MAX_INLINE_XATTR < crate::uapi::DEF_ADDRS_PER_INODE as u32);
}
