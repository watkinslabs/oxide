// `IORING_OP_POLL_ADD` / `IORING_OP_POLL_REMOVE` argument decode, and the
// readiness-mask arithmetic the armed poll runs on.
//
// A polled entry is armed against a description's readiness and completes when
// that readiness arrives, so it can never run inside the submission that
// issued it. What it asks for, what it reports, and whether it stays armed are
// decided here (CLAUDE.md phantom-test rule); the arming lives in
// `io_uring::poll`.

use syscall::errno::Errno;

use crate::io_uring_sqe::Sqe;

/// `IORING_POLL_ADD_MULTI` — stay armed and report every readiness change.
pub const IORING_POLL_ADD_MULTI:        u32 = 1 << 0;
/// `IORING_POLL_UPDATE_EVENTS` — the update replaces the event mask.
pub const IORING_POLL_UPDATE_EVENTS:    u32 = 1 << 1;
/// `IORING_POLL_UPDATE_USER_DATA` — the update replaces `user_data`.
pub const IORING_POLL_UPDATE_USER_DATA: u32 = 1 << 2;
/// `IORING_POLL_ADD_LEVEL` — report readiness for as long as it lasts, rather
/// than once per transition.
pub const IORING_POLL_ADD_LEVEL:        u32 = 1 << 3;

/// Every flag `IORING_OP_POLL_REMOVE` accepts.
pub const POLL_UPDATE_VALID_FLAGS: u32 =
    IORING_POLL_UPDATE_EVENTS | IORING_POLL_UPDATE_USER_DATA | IORING_POLL_ADD_MULTI;

/// `POLLNVAL` — the description the poll names is not one. The rest of the
/// poll ABI bits come from `vfs`, which does not carry this one.
pub const POLL_NVAL: u32 = 0x0020;

/// The conditions an armed poll always reports, whether or not the caller
/// asked for them: an error, a hangup, a peer hangup and an invalid
/// description are not something a waiter can choose to keep waiting through.
pub const POLL_ALWAYS: u32 = vfs::POLL_ERR | vfs::POLL_HUP | POLL_NVAL | vfs::POLL_RDHUP;

/// One decoded `IORING_OP_POLL_ADD`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PollPrep {
    /// The readiness the caller asked about, plus the always-reported set.
    pub events: u32,
    /// Stay armed after the first report.
    pub multishot: bool,
    /// Report a readiness that is merely still true, not only one that has
    /// just become true.
    pub level: bool,
}

/// Decode `IORING_OP_POLL_ADD`. The event mask sits in the per-opcode flags
/// word and the poll's OWN flags in `len`, which is the opposite of every
/// other opcode — reading them the other way round arms a poll for the flag
/// bits and treats the mask as flags. # C: O(1)
pub fn prep_poll_add(sqe: &Sqe) -> Result<PollPrep, Errno> {
    use crate::io_uring_abi::ops::IOSQE_CQE_SKIP_SUCCESS;
    if sqe.buf_index != 0 || sqe.off != 0 || sqe.addr != 0 { return Err(Errno::Einval); }
    let flags = sqe.len;
    if flags & !IORING_POLL_ADD_MULTI != 0 { return Err(Errno::Einval); }
    let multishot = flags & IORING_POLL_ADD_MULTI != 0;
    // A poll that reports repeatedly and a poll that says nothing when it
    // succeeds cancel each other out, so the pair is refused.
    if multishot && sqe.flags & IOSQE_CQE_SKIP_SUCCESS != 0 { return Err(Errno::Einval); }
    Ok(PollPrep {
        events: sqe.op_flags | POLL_ALWAYS,
        multishot,
        level: flags & IORING_POLL_ADD_LEVEL != 0,
    })
}

/// What an `IORING_OP_POLL_REMOVE` asks for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PollUpdate {
    /// `user_data` of the armed poll to act on.
    pub target: u64,
    /// Replacement event mask, when the caller asked for one.
    pub events: Option<u32>,
    /// Replacement `user_data`, when the caller asked for one.
    pub user_data: Option<u64>,
    /// The replacement arming stays armed.
    pub multishot: bool,
}

impl PollUpdate {
    /// Whether this is a plain cancellation rather than a re-arm. # C: O(1)
    pub fn is_removal(&self) -> bool { self.events.is_none() && self.user_data.is_none() }
}

/// Decode `IORING_OP_POLL_REMOVE`. # C: O(1)
pub fn prep_poll_remove(sqe: &Sqe) -> Result<PollUpdate, Errno> {
    if sqe.buf_index != 0 || sqe.splice_fd_in != 0 { return Err(Errno::Einval); }
    let flags = sqe.len;
    if flags & !POLL_UPDATE_VALID_FLAGS != 0 { return Err(Errno::Einval); }
    let events = flags & IORING_POLL_UPDATE_EVENTS != 0;
    let user_data = flags & IORING_POLL_UPDATE_USER_DATA != 0;
    // Staying armed is a property of an arming, so it says nothing on its own.
    if flags == IORING_POLL_ADD_MULTI { return Err(Errno::Einval); }
    // The replacement `user_data` word must be silent when it is not wanted,
    // so a caller cannot believe it changed something it did not.
    if !user_data && sqe.off != 0 { return Err(Errno::Einval); }
    if !events && sqe.op_flags != 0 { return Err(Errno::Einval); }
    Ok(PollUpdate {
        target: sqe.addr,
        events: if events { Some(sqe.op_flags | POLL_ALWAYS) } else { None },
        user_data: if user_data { Some(sqe.off) } else { None },
        multishot: flags & IORING_POLL_ADD_MULTI != 0,
    })
}

/// The readiness an armed poll reports, or `None` when nothing it asked about
/// has happened yet. # C: O(1)
pub fn poll_hit(ready: u32, events: u32) -> Option<u32> {
    let hit = ready & events;
    if hit == 0 { None } else { Some(hit) }
}

/// Whether an armed poll stays armed after reporting `hit`. A repeating poll
/// stops at a hangup or an error: the description will report that same
/// condition forever, so staying armed would spin. # C: O(1)
pub fn poll_rearms(multishot: bool, hit: u32) -> bool {
    multishot && hit & POLL_ALWAYS == 0
}

/// The readiness mask an operation that reported `EAGAIN` should be armed
/// against. A read waits for data, everything else for room to write; both
/// also wake on an error or a hangup, because neither will ever be followed by
/// the readiness the operation was waiting for. # C: O(1)
pub fn retry_mask(reads: bool) -> u32 {
    if reads { vfs::POLL_IN | POLL_ALWAYS } else { vfs::POLL_OUT | POLL_ALWAYS }
}

#[cfg(test)]
#[path = "poll/tests.rs"]
mod tests;
