//! Eventfd counter arithmetic and flag admission — the whole decision surface
//! of eventfd(2), with no target gate so `cargo test -p fs` proves it.
//!
//! Every boundary here is at `u64::MAX` or `u64::MAX - 1` and every one of
//! them is off by one from a plausible alternative, which is exactly why they
//! are named and tested rather than open-coded at the call sites.

/// `EFD_SEMAPHORE` — read consumes 1 instead of draining the counter.
pub const EFD_SEMAPHORE: u64 = 1;
/// `EFD_CLOEXEC` — aliases `O_CLOEXEC`.
pub const EFD_CLOEXEC: u64 = 0o2_000_000;
/// `EFD_NONBLOCK` — aliases `O_NONBLOCK`.
pub const EFD_NONBLOCK: u64 = 0o0_004_000;
/// Every flag `eventfd2` accepts; anything else is EINVAL.
pub const EFD_FLAGS_SET: u64 = EFD_SEMAPHORE | EFD_CLOEXEC | EFD_NONBLOCK;

/// Both `read(2)` and `write(2)` transfer exactly one `u64`.
pub const EVENTFD_RECORD: usize = core::mem::size_of::<u64>();

/// Reject unknown flag bits. # C: O(1)
pub fn flags_valid(flags: u64) -> bool { flags & !EFD_FLAGS_SET == 0 }

/// Legacy 1-argument `eventfd(2)` has no flags word; it always runs with
/// `flags == 0`. Its own argument is the initial counter value, so a caller
/// passing what it thinks are flags must not have them applied.
/// # C: O(1)
pub const LEGACY_FLAGS: u64 = 0;

/// `eventfd_ctx_do_read`: the value a read transfers, and the new counter.
/// `None` when the counter is 0 (the caller blocks or returns EAGAIN).
/// Semaphore mode transfers 1; otherwise the whole counter drains.
/// # C: O(1)
pub fn do_read(count: u64, semaphore: bool) -> Option<(u64, u64)> {
    if count == 0 { return None; }
    let transferred = if semaphore { 1 } else { count };
    Some((transferred, count - transferred))
}

/// Whether `add` fits: `ULLONG_MAX - count > add`. Strict, so the counter can
/// never be driven to `u64::MAX` by a write — that value is reserved for the
/// in-kernel signalling path and is reported to poll as an error condition.
/// # C: O(1)
pub fn write_fits(count: u64, add: u64) -> bool { u64::MAX - count > add }

/// `write(2)` may never carry `ULLONG_MAX`: it is the sentinel that would
/// otherwise be indistinguishable from the overflow state.
/// # C: O(1)
pub fn write_value_valid(add: u64) -> bool { add != u64::MAX }

/// `eventfd_poll` mask for a counter value.
/// # C: O(1)
pub fn poll_mask(count: u64) -> u32 {
    let mut m = 0;
    if count > 0 { m |= vfs::POLL_IN; }
    if count == u64::MAX { m |= vfs::POLL_ERR; }
    if u64::MAX - 1 > count { m |= vfs::POLL_OUT; }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_three_documented_flags_are_accepted() {
        assert!(flags_valid(0));
        assert!(flags_valid(EFD_SEMAPHORE | EFD_CLOEXEC | EFD_NONBLOCK));
        assert!(!flags_valid(1 << 1), "EFD_SEMAPHORE is bit 0; bit 1 is not a flag");
        assert!(!flags_valid(0o200_000), "O_DIRECTORY is not an eventfd flag");
        assert!(!flags_valid(u64::MAX));
        assert_eq!(LEGACY_FLAGS, 0);
    }

    #[test]
    fn a_normal_read_drains_the_whole_counter() {
        assert_eq!(do_read(5, false), Some((5, 0)));
        assert_eq!(do_read(u64::MAX, false), Some((u64::MAX, 0)));
        assert_eq!(do_read(0, false), None);
    }

    #[test]
    fn a_semaphore_read_consumes_exactly_one() {
        assert_eq!(do_read(3, true), Some((1, 2)));
        assert_eq!(do_read(1, true), Some((1, 0)));
        assert_eq!(do_read(0, true), None, "an empty semaphore blocks, it does not return 0");
        assert_eq!(do_read(u64::MAX, true), Some((1, u64::MAX - 1)));
    }

    #[test]
    fn a_write_never_reaches_the_overflow_sentinel() {
        // The bound is STRICT: a write that would land exactly on u64::MAX is
        // rejected, so only the in-kernel signalling path can produce it.
        assert!(write_fits(0, u64::MAX - 1));
        assert!(!write_fits(0, u64::MAX), "the sentinel itself never fits");
        assert!(write_fits(u64::MAX - 2, 1));
        assert!(!write_fits(u64::MAX - 1, 1));
        // The test is on the SUM, not on the counter: at the last writable
        // value a zero-valued write still fits, even though poll already
        // reports no write capacity.
        assert!(write_fits(u64::MAX - 1, 0));
        assert!(write_fits(u64::MAX - 2, 0));
        // The sentinel is only reachable from in-kernel signalling, and once
        // there nothing fits — not even a zero write.
        assert!(!write_fits(u64::MAX, 0));
    }

    #[test]
    fn writing_the_sentinel_value_is_rejected_before_any_capacity_test() {
        assert!(!write_value_valid(u64::MAX));
        assert!(write_value_valid(u64::MAX - 1));
        assert!(write_value_valid(0), "a zero write is legal and is a no-op bump");
    }

    #[test]
    fn poll_reports_in_out_and_the_overflow_error() {
        assert_eq!(poll_mask(0), vfs::POLL_OUT, "empty: writable, never readable");
        assert_eq!(poll_mask(1), vfs::POLL_IN | vfs::POLL_OUT);
        // u64::MAX - 1 is the first value with no write capacity left.
        assert_eq!(poll_mask(u64::MAX - 2), vfs::POLL_IN | vfs::POLL_OUT);
        assert_eq!(poll_mask(u64::MAX - 1), vfs::POLL_IN);
        assert_eq!(poll_mask(u64::MAX), vfs::POLL_IN | vfs::POLL_ERR);
    }

    #[test]
    fn a_record_is_eight_bytes() { assert_eq!(EVENTFD_RECORD, 8); }
}
