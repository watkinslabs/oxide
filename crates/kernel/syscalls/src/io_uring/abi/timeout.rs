// `IORING_OP_TIMEOUT`, `IORING_OP_LINK_TIMEOUT` and `IORING_OP_TIMEOUT_REMOVE`
// argument decode.
//
// A timeout is the first operation that cannot run inside the submission that
// issued it: it has to sit somewhere until either its clock runs out or the
// ring posts enough completions. Everything about WHICH of those two ends it,
// and what the entry reports when it does, is decided here so it is testable
// without a ring (CLAUDE.md phantom-test rule); the arming itself lives in
// `io_uring::timeout`.

use syscall::errno::Errno;

use crate::io_uring_sqe::Sqe;

/// `IORING_TIMEOUT_ABS` — the time argument is a deadline, not a duration.
pub const IORING_TIMEOUT_ABS:            u32 = 1 << 0;
/// `IORING_TIMEOUT_UPDATE` — re-arm an armed timeout instead of removing it.
pub const IORING_TIMEOUT_UPDATE:         u32 = 1 << 1;
/// `IORING_TIMEOUT_BOOTTIME` — measure against `CLOCK_BOOTTIME`.
pub const IORING_TIMEOUT_BOOTTIME:       u32 = 1 << 2;
/// `IORING_TIMEOUT_REALTIME` — measure against `CLOCK_REALTIME`.
pub const IORING_TIMEOUT_REALTIME:       u32 = 1 << 3;
/// `IORING_LINK_TIMEOUT_UPDATE` — the update targets a link timeout.
pub const IORING_LINK_TIMEOUT_UPDATE:    u32 = 1 << 4;
/// `IORING_TIMEOUT_ETIME_SUCCESS` — expiry is not a failure.
pub const IORING_TIMEOUT_ETIME_SUCCESS:  u32 = 1 << 5;
/// `IORING_TIMEOUT_MULTISHOT` — re-arm after each expiry.
pub const IORING_TIMEOUT_MULTISHOT:      u32 = 1 << 6;
/// `IORING_TIMEOUT_IMMEDIATE_ARG` — `addr` IS the nanosecond count.
pub const IORING_TIMEOUT_IMMEDIATE_ARG:  u32 = 1 << 7;

/// The two clock-selecting bits. More than one set is `EINVAL`.
pub const IORING_TIMEOUT_CLOCK_MASK: u32 = IORING_TIMEOUT_BOOTTIME | IORING_TIMEOUT_REALTIME;
/// The two bits that turn `TIMEOUT_REMOVE` into an update.
pub const IORING_TIMEOUT_UPDATE_MASK: u32 = IORING_TIMEOUT_UPDATE | IORING_LINK_TIMEOUT_UPDATE;

/// Every flag an arming timeout accepts. `UPDATE`/`LINK_TIMEOUT_UPDATE` are
/// removal-side bits, so they are absent here.
pub const TIMEOUT_VALID_FLAGS: u32 =
    IORING_TIMEOUT_ABS | IORING_TIMEOUT_CLOCK_MASK | IORING_TIMEOUT_ETIME_SUCCESS
    | IORING_TIMEOUT_MULTISHOT | IORING_TIMEOUT_IMMEDIATE_ARG;

/// Every flag the update form of `TIMEOUT_REMOVE` accepts.
pub const TIMEOUT_UPDATE_VALID_FLAGS: u32 =
    IORING_TIMEOUT_UPDATE_MASK | IORING_TIMEOUT_ABS | IORING_TIMEOUT_IMMEDIATE_ARG;

/// `CLOCK_REALTIME`.
pub const CLOCK_REALTIME: u32 = 0;
/// `CLOCK_MONOTONIC`.
pub const CLOCK_MONOTONIC: u32 = 1;
/// `CLOCK_BOOTTIME`.
pub const CLOCK_BOOTTIME: u32 = 7;

/// `sqe.len` an arming timeout must carry — one timespec.
pub const TIMEOUT_LEN: u32 = 1;

/// Where an armed timeout takes its time from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimeArg {
    /// `addr` is a raw nanosecond count.
    Nanos(u64),
    /// `addr` is a user pointer to a `struct __kernel_timespec`.
    UserTimespec(u64),
}

/// One decoded arming timeout.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TimeoutPrep {
    /// `sqe.off` — how many completions must be posted before the timeout is
    /// satisfied by count rather than by clock. `0` = clock only.
    pub count: u64,
    /// The clock the time argument is stated on.
    pub clockid: u32,
    /// The time argument is a deadline on `clockid` rather than a duration.
    pub abs: bool,
    /// Expiry is a normal result rather than a failure.
    pub etime_success: bool,
    /// Re-arm after each expiry.
    pub multishot: bool,
    /// How many further expiries a bounded multishot has left. `0` with
    /// `multishot` set means unbounded.
    pub repeats: u64,
    pub time: TimeArg,
}

/// Which clock the flags select. # C: O(1)
pub fn clock_of(flags: u32) -> u32 {
    if flags & IORING_TIMEOUT_BOOTTIME != 0 { return CLOCK_BOOTTIME; }
    if flags & IORING_TIMEOUT_REALTIME != 0 { return CLOCK_REALTIME; }
    CLOCK_MONOTONIC
}

/// Decode an arming timeout. `is_link` selects `IORING_OP_LINK_TIMEOUT`, whose
/// only difference is that a completion count is meaningless — the entry it
/// guards is the thing that ends it. # C: O(1)
pub fn prep_timeout(sqe: &Sqe, is_link: bool) -> Result<TimeoutPrep, Errno> {
    if sqe.addr3 != 0 || sqe.pad2 != 0 { return Err(Errno::Einval); }
    if sqe.buf_index != 0 || sqe.len != TIMEOUT_LEN || sqe.splice_fd_in != 0 {
        return Err(Errno::Einval);
    }
    if sqe.off != 0 && is_link { return Err(Errno::Einval); }
    let flags = sqe.op_flags;
    if flags & !TIMEOUT_VALID_FLAGS != 0 { return Err(Errno::Einval); }
    if (flags & IORING_TIMEOUT_CLOCK_MASK).count_ones() > 1 { return Err(Errno::Einval); }
    // A repeating timeout restated as a deadline would fire once and then be
    // permanently in the past, so the pair is refused rather than silently
    // degenerating into a spin.
    if flags & IORING_TIMEOUT_MULTISHOT != 0 && flags & IORING_TIMEOUT_ABS != 0 {
        return Err(Errno::Einval);
    }
    let multishot = flags & IORING_TIMEOUT_MULTISHOT != 0;
    Ok(TimeoutPrep {
        count: sqe.off,
        clockid: clock_of(flags),
        abs: flags & IORING_TIMEOUT_ABS != 0,
        etime_success: flags & IORING_TIMEOUT_ETIME_SUCCESS != 0,
        multishot,
        repeats: if multishot { sqe.off } else { 0 },
        time: if flags & IORING_TIMEOUT_IMMEDIATE_ARG != 0 {
            TimeArg::Nanos(sqe.addr)
        } else {
            TimeArg::UserTimespec(sqe.addr)
        },
    })
}

/// Whether a multishot timeout keeps going after this expiry. An unbounded
/// repeat (`count == 0`) never stops on its own; a bounded one stops once it
/// has fired the requested number of times. `repeats` is consumed in place.
/// # C: O(1)
pub fn multishot_continues(count: u64, repeats: &mut u64) -> bool {
    if count == 0 { return true; }
    if *repeats > 0 { *repeats -= 1; }
    *repeats > 0
}

/// What kind of `TIMEOUT_REMOVE` the flags ask for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RemoveKind {
    /// Cancel the named timeout.
    Remove,
    /// Re-arm the named plain timeout with a new time.
    Update,
    /// Re-arm the named link timeout with a new time.
    UpdateLink,
}

/// One decoded `IORING_OP_TIMEOUT_REMOVE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RemovePrep {
    /// `user_data` of the timeout to act on.
    pub target: u64,
    pub kind: RemoveKind,
    pub clockid: u32,
    pub abs: bool,
    /// Only meaningful for the two update kinds.
    pub time: TimeArg,
}

/// Decode `IORING_OP_TIMEOUT_REMOVE`. # C: O(1)
pub fn prep_timeout_remove(sqe: &Sqe) -> Result<RemovePrep, Errno> {
    use crate::io_uring_abi::ops::{IOSQE_BUFFER_SELECT, IOSQE_FIXED_FILE};
    if sqe.flags & (IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT) != 0 { return Err(Errno::Einval); }
    if sqe.addr3 != 0 || sqe.pad2 != 0 { return Err(Errno::Einval); }
    if sqe.buf_index != 0 || sqe.len != 0 || sqe.splice_fd_in != 0 { return Err(Errno::Einval); }
    let flags = sqe.op_flags;
    let kind = if flags & IORING_TIMEOUT_UPDATE_MASK != 0 {
        if (flags & IORING_TIMEOUT_CLOCK_MASK).count_ones() > 1 { return Err(Errno::Einval); }
        if flags & !TIMEOUT_UPDATE_VALID_FLAGS != 0 { return Err(Errno::Einval); }
        if flags & IORING_LINK_TIMEOUT_UPDATE != 0 { RemoveKind::UpdateLink } else { RemoveKind::Update }
    } else {
        // Removal carries no flags at all: there is nothing about a
        // cancellation for a clock or an absolute deadline to describe.
        if flags != 0 { return Err(Errno::Einval); }
        RemoveKind::Remove
    };
    Ok(RemovePrep {
        target: sqe.addr,
        kind,
        clockid: clock_of(flags),
        abs: flags & IORING_TIMEOUT_ABS != 0,
        time: if flags & IORING_TIMEOUT_IMMEDIATE_ARG != 0 {
            TimeArg::Nanos(sqe.off)
        } else {
            TimeArg::UserTimespec(sqe.off)
        },
    })
}

#[cfg(test)]
#[path = "timeout/tests.rs"]
mod tests;
