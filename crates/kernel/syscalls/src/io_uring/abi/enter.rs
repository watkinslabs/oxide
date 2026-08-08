// `io_uring_enter(2)` argument decode and the submit/wait decisions.
//
// Kept out of the (kernel-gated) slot file so the flag ladder, the extended
// argument forms and the wraparound arithmetic are unit-tested (CLAUDE.md
// phantom-test rule).

use syscall::errno::Errno;

/// `IORING_ENTER_GETEVENTS` — wait for `min_complete` completions.
pub const IORING_ENTER_GETEVENTS:       u32 = 1 << 0;
/// `IORING_ENTER_SQ_WAKEUP` — wake the SQ poll thread.
pub const IORING_ENTER_SQ_WAKEUP:       u32 = 1 << 1;
/// `IORING_ENTER_SQ_WAIT` — wait for the SQ poll thread to drain the ring.
pub const IORING_ENTER_SQ_WAIT:         u32 = 1 << 2;
/// `IORING_ENTER_EXT_ARG` — `argp` is a `struct io_uring_getevents_arg`.
pub const IORING_ENTER_EXT_ARG:         u32 = 1 << 3;
/// `IORING_ENTER_REGISTERED_RING` — `fd` indexes the registered-ring array.
pub const IORING_ENTER_REGISTERED_RING: u32 = 1 << 4;
/// `IORING_ENTER_ABS_TIMER` — the wait timespec is absolute, not relative.
pub const IORING_ENTER_ABS_TIMER:       u32 = 1 << 5;
/// `IORING_ENTER_EXT_ARG_REG` — `argp` is an offset into a registered wait region.
pub const IORING_ENTER_EXT_ARG_REG:     u32 = 1 << 6;
/// `IORING_ENTER_NO_IOWAIT` — do not account the wait as iowait.
pub const IORING_ENTER_NO_IOWAIT:       u32 = 1 << 7;

/// Every `io_uring_enter` flag; a bit outside this mask is `EINVAL`.
pub const IORING_ENTER_FLAGS: u32 =
    IORING_ENTER_GETEVENTS | IORING_ENTER_SQ_WAKEUP | IORING_ENTER_SQ_WAIT
    | IORING_ENTER_EXT_ARG | IORING_ENTER_REGISTERED_RING | IORING_ENTER_ABS_TIMER
    | IORING_ENTER_EXT_ARG_REG | IORING_ENTER_NO_IOWAIT;

/// `sizeof(struct io_uring_getevents_arg)` — {sigmask u64, sigmask_sz u32,
/// min_wait_usec u32, ts u64}.
pub const GETEVENTS_ARG_BYTES: u64 = 24;
/// `sizeof(struct io_uring_reg_wait)` — the registered-wait-region form.
pub const REG_WAIT_BYTES: u64 = 64;
/// `io_uring_reg_wait.flags` bit: the embedded timespec is valid.
pub const IORING_REG_WAIT_TS: u32 = 1 << 0;
/// Nanoseconds per microsecond — `min_wait_usec` is microseconds.
pub const NSEC_PER_USEC: u64 = 1_000;

/// Which shape `argp` has for this call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArgKind {
    /// No `IORING_ENTER_EXT_ARG`: `argp` is a bare `sigset_t *` and `argsz`
    /// its size.
    BareSigmask,
    /// `struct io_uring_getevents_arg` at `argp`.
    Getevents,
    /// `struct io_uring_reg_wait` inside the ring's registered wait region.
    RegisteredWait,
}

/// The decoded wait parameters, whichever argument shape supplied them.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ExtArg {
    /// User pointer to the sigset to install for the wait; 0 = leave the mask.
    pub sig: u64,
    /// Size the caller claims for that sigset.
    pub sigsz: u64,
    /// Minimum time to wait before a partial completion batch returns.
    pub min_wait_ns: u64,
    /// Wait timeout, when the caller supplied a timespec.
    pub ts: Option<(i64, i64)>,
    /// The timespec is an absolute deadline rather than a relative timeout.
    pub abs: bool,
    /// Account the wait as iowait.
    pub iowait: bool,
}

/// Reject unknown `io_uring_enter` flags before the ring fd is even resolved.
/// # C: O(1)
pub fn validate_flags(flags: u32) -> Result<(), Errno> {
    if flags & !IORING_ENTER_FLAGS != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Which argument shape the flags select, with the size check that shape
/// demands. The two extended-argument flags are mutually exclusive in the
/// sense that `EXT_ARG_REG` only has meaning with `EXT_ARG` set: without it
/// the pointer is a bare sigset and the register flag is ignored.
/// # C: O(1)
pub fn arg_kind(flags: u32, argsz: u64) -> Result<ArgKind, Errno> {
    if flags & IORING_ENTER_EXT_ARG == 0 { return Ok(ArgKind::BareSigmask); }
    if flags & IORING_ENTER_EXT_ARG_REG != 0 {
        if argsz != REG_WAIT_BYTES { return Err(Errno::Einval); }
        return Ok(ArgKind::RegisteredWait);
    }
    if argsz != GETEVENTS_ARG_BYTES { return Err(Errno::Einval); }
    Ok(ArgKind::Getevents)
}

/// Decode `struct io_uring_getevents_arg`. `ts` is a user pointer to a
/// timespec, read separately by the caller. # C: O(1)
pub fn decode_getevents(b: &[u8; GETEVENTS_ARG_BYTES as usize]) -> (u64, u64, u64, u64) {
    let sigmask = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let sigmask_sz = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
    let min_wait_usec = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
    let ts = u64::from_le_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]);
    (sigmask, sigmask_sz as u64, min_wait_usec as u64, ts)
}

/// Decode `struct io_uring_reg_wait` — {ts:{sec,nsec}, min_wait_usec, flags,
/// sigmask, sigmask_sz, pad}. Unknown `flags` bits are `EINVAL`; the embedded
/// timespec counts only when `IORING_REG_WAIT_TS` says so. # C: O(1)
pub fn decode_reg_wait(b: &[u8; REG_WAIT_BYTES as usize], enter_flags: u32)
    -> Result<ExtArg, Errno>
{
    let g64 = |o: usize| {
        let mut v = [0u8; 8]; v.copy_from_slice(&b[o..o + 8]); i64::from_le_bytes(v)
    };
    let g32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    let sec = g64(0);
    let nsec = g64(8);
    let min_wait_usec = g32(16) as u64;
    let flags = g32(20);
    if flags & !IORING_REG_WAIT_TS != 0 { return Err(Errno::Einval); }
    let sigmask = g64(24) as u64;
    let sigmask_sz = g32(32) as u64;
    Ok(ExtArg {
        sig: sigmask, sigsz: sigmask_sz,
        min_wait_ns: min_wait_usec.saturating_mul(NSEC_PER_USEC),
        ts: if flags & IORING_REG_WAIT_TS != 0 { Some((sec, nsec)) } else { None },
        abs: enter_flags & IORING_ENTER_ABS_TIMER != 0,
        iowait: enter_flags & IORING_ENTER_NO_IOWAIT == 0,
    })
}

/// The bare-sigmask form: `argp` IS the sigset pointer and `argsz` its size.
/// # C: O(1)
pub fn bare_sigmask_arg(argp: u64, argsz: u64, flags: u32) -> ExtArg {
    ExtArg {
        sig: argp, sigsz: argsz, min_wait_ns: 0, ts: None,
        abs: flags & IORING_ENTER_ABS_TIMER != 0,
        iowait: flags & IORING_ENTER_NO_IOWAIT == 0,
    }
}

/// CQEs the ring can still accept. Head and tail are free-running counters
/// masked only at access time, so the difference is wraparound-correct.
/// # C: O(1)
pub fn cq_space(cq_tail: u32, cq_head: u32, cq_entries: u32) -> u32 {
    cq_entries.saturating_sub(cq_tail.wrapping_sub(cq_head))
}

/// Whether a completion can be posted into the ring proper. A full ring does
/// not drop the completion: it goes to the overflow backlog, which is what
/// `IORING_FEAT_NODROP` promises. # C: O(1)
pub fn cq_has_room(cq_tail: u32, cq_head: u32, cq_entries: u32) -> bool {
    cq_space(cq_tail, cq_head, cq_entries) > 0
}

/// Completions posted and not yet reaped. # C: O(1)
pub fn cq_ready(cq_tail: u32, cq_head: u32) -> u32 { cq_tail.wrapping_sub(cq_head) }

/// Whether an SQ index array entry names a real SQE; a bad index is counted in
/// `sq_dropped` and skipped. # C: O(1)
pub fn sq_index_valid(idx: u32, sq_entries: u32) -> bool { idx < sq_entries }

/// `min_complete` is clamped to the CQ depth: a caller asking for more
/// completions than the ring can hold would otherwise wait forever.
/// # C: O(1)
pub fn wait_min_events(min_complete: u32, cq_entries: u32) -> u32 {
    if min_complete > cq_entries { cq_entries } else { min_complete }
}

/// Whether the waiter's condition is met. # C: O(1)
pub fn should_wake(ready: u32, min_events: u32) -> bool { ready >= min_events }

/// The submit half's contribution to the return value, and whether the wait
/// half runs at all. A submission that stopped short of `to_submit` reports
/// what it did and never waits. # C: O(1)
pub fn runs_getevents(submitted: i64, to_submit: u32, flags: u32) -> bool {
    if flags & IORING_ENTER_GETEVENTS == 0 { return false; }
    if to_submit == 0 { return true; }
    submitted == to_submit as i64
}

/// Fold the submit and wait halves into the syscall's return value: the
/// submitted count wins whenever anything was submitted, so a wait error is
/// only ever reported by a call that submitted nothing. # C: O(1)
pub fn enter_result(submitted: i64, wait_rv: i64) -> i64 {
    if submitted != 0 { submitted } else { wait_rv }
}

/// The wait's own return value: a timeout or interruption is downgraded to
/// success when there is something for the caller to reap. # C: O(1)
pub fn wait_result(rv: i64, cq_nonempty: bool) -> i64 {
    if cq_nonempty { 0 } else { rv }
}

#[cfg(test)]
#[path = "enter/tests.rs"]
mod tests;
