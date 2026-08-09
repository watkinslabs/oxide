use crate::ioport::ladder::{ioperm_check, iopl_check, IoplAction, IOPL_MAX};
use crate::ioport::bitmap::IO_BITMAP_BITS;
use syscall::errno::Errno;

/// The range test runs BEFORE the capability test. An unprivileged caller
/// asking for a malformed range must learn the range is wrong, not that it
/// lacks a privilege which would not have helped.
#[test]
fn ioperm_rejects_the_range_before_it_checks_privilege() {
    assert_eq!(ioperm_check(0, 0, true, false), Err(Errno::Einval), "num == 0");
    assert_eq!(ioperm_check(IO_BITMAP_BITS, 1, true, false), Err(Errno::Einval), "past the port space");
    assert_eq!(ioperm_check(1, IO_BITMAP_BITS, true, false), Err(Errno::Einval), "end past the port space");
    assert_eq!(ioperm_check(u64::MAX, 2, true, false), Err(Errno::Einval), "wrapping sum");
    // Only once the range is legal does the missing capability surface.
    assert_eq!(ioperm_check(0x3f8, 8, true, false), Err(Errno::Eperm));
}

/// `num == 0` is EINVAL, not a no-op success: the reference's `from + num <=
/// from` arm catches it, and a caller probing with a zero-length range must
/// see the same answer here.
#[test]
fn ioperm_zero_length_is_einval_at_every_base() {
    for from in [0u64, 1, 0x3f8, IO_BITMAP_BITS - 1] {
        assert_eq!(ioperm_check(from, 0, true, true), Err(Errno::Einval), "from={from}");
    }
}

/// The last legal port is `IO_BITMAP_BITS - 1`, and a range ending exactly at
/// the top is legal. An off-by-one either way is a real defect: one direction
/// refuses a legitimate grant, the other writes past the map.
#[test]
fn ioperm_accepts_exactly_the_port_space_and_no_more() {
    assert_eq!(ioperm_check(0, IO_BITMAP_BITS, true, true), Ok(()));
    assert_eq!(ioperm_check(IO_BITMAP_BITS - 1, 1, true, true), Ok(()));
    assert_eq!(ioperm_check(0, IO_BITMAP_BITS + 1, true, true), Err(Errno::Einval));
    assert_eq!(ioperm_check(IO_BITMAP_BITS - 1, 2, true, true), Err(Errno::Einval));
}

/// WITHDRAWING ports needs no privilege. A process that gained ports and then
/// dropped root must still be able to give them back.
#[test]
fn ioperm_withdrawal_is_unprivileged() {
    assert_eq!(ioperm_check(0x3f8, 8, false, false), Ok(()));
    assert_eq!(ioperm_check(0x3f8, 8, true, false), Err(Errno::Eperm));
}

/// `level > 3` is EINVAL and it is decided FIRST — before the no-change
/// shortcut and before the capability test.
#[test]
fn iopl_rejects_an_out_of_range_level_first() {
    assert_eq!(iopl_check(4, 0, true), Err(Errno::Einval));
    assert_eq!(iopl_check(u32::MAX, 3, true), Err(Errno::Einval));
    assert_eq!(IOPL_MAX, 3);
}

/// Re-asserting the level already held succeeds WITHOUT the capability, and
/// LOWERING the level is likewise unprivileged. Only raising it needs
/// `CAP_SYS_RAWIO`.
#[test]
fn iopl_only_charges_privilege_for_a_raise() {
    assert_eq!(iopl_check(0, 0, false), Ok(IoplAction::Unchanged));
    assert_eq!(iopl_check(3, 3, false), Ok(IoplAction::Unchanged));
    assert_eq!(iopl_check(1, 3, false), Ok(IoplAction::Set(1)), "lowering is free");
    assert_eq!(iopl_check(3, 0, false), Err(Errno::Eperm), "raising is not");
    assert_eq!(iopl_check(3, 0, true), Ok(IoplAction::Set(3)));
    assert_eq!(iopl_check(1, 0, false), Err(Errno::Eperm), "a raise to 1 still costs the cap");
}
