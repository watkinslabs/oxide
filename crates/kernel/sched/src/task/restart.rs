// Per-task `restart_block` — Linux `struct restart_block`
// (`include/linux/restart_block.h`), the continuation `restart_syscall(2)`
// dispatches through after a signal interrupted a resumable call.
//
// Linux stores a function pointer plus a per-kind payload union. `docs/07§5`
// bans `dyn`/indirect-call tables in the kernel, so the pointer is a `kind`
// discriminant owned here and the continuation bodies live with the syscalls
// that arm them (`crates/kernel/syscalls/src/219_restart_syscall.rs`). One
// owner, one payload, no parallel registry.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Linux `do_no_restart_syscall` — an unarmed block; `restart_syscall(2)`
/// against it reports EINTR.
pub const RESTART_NONE: u32 = 0;
/// Linux `hrtimer_nanosleep_restart`: resume an absolute-deadline sleep.
/// Payload: `[deadline_ns, rmtp_user_ptr, 0, 0, 0, 0]`. Armed by the RELATIVE
/// form of both `nanosleep(2)` and `clock_nanosleep(2)`; the `TIMER_ABSTIME`
/// form arms nothing (`kernel/time/hrtimer.c:2449-2453`).
pub const RESTART_NANOSLEEP: u32 = 1;
/// Linux `do_restart_poll` (`fs/select.c:1042-1058`): resume `poll(2)`, whose
/// `int timeout_msecs` argument cannot carry the residual timeout back to
/// userspace the way `ppoll`'s timespec does.
/// Payload: `[ufds, nfds, has_timeout, end_time_ns, 0, 0]`.
pub const RESTART_POLL: u32 = 2;
/// Linux `futex_wait_restart` (`kernel/futex/waitwake.c:773-785`): resume a
/// TIMED `FUTEX_WAIT`/`FUTEX_WAIT_BITSET` against the SAME absolute deadline.
/// Payload: `[uaddr, op_full, val, bitset, deadline_ns, 0]`.
pub const RESTART_FUTEX: u32 = 3;

/// Payload slots per block, matching the widest continuation Linux stores
/// (`futex`: uaddr, val, flags, bitset, time, uaddr2).
pub const RESTART_ARGS: usize = 6;

/// Linux `struct restart_block`. Single-writer per task (only the owning task
/// arms or consumes it), so plain atomics carry it without a lock.
pub struct RestartBlock {
    kind: AtomicU32,
    args: [AtomicU64; RESTART_ARGS],
}

impl RestartBlock {
    /// Unarmed block — Linux's `restart_block.fn = do_no_restart_syscall`.
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            kind: AtomicU32::new(RESTART_NONE),
            args: [
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
            ],
        }
    }

    /// Linux `set_restart_fn`: arm the continuation. Callers pair this with a
    /// `-ERESTART_RESTARTBLOCK` return.
    /// # C: O(RESTART_ARGS)
    pub fn arm(&self, kind: u32, args: [u64; RESTART_ARGS]) {
        for (slot, v) in self.args.iter().zip(args.iter()) { slot.store(*v, Ordering::Relaxed); }
        self.kind.store(kind, Ordering::Release);
    }

    /// Linux `restart_block.fn = do_no_restart_syscall` at syscall entry: a
    /// fresh resumable call must not inherit the previous one's continuation.
    /// # C: O(1)
    pub fn disarm(&self) { self.kind.store(RESTART_NONE, Ordering::Release); }

    /// Armed continuation kind. `RESTART_NONE` when unarmed.
    /// # C: O(1)
    pub fn kind(&self) -> u32 { self.kind.load(Ordering::Acquire) }

    /// Payload of the armed continuation. Linux leaves the block armed across
    /// a resume so repeated interruptions keep resuming the SAME absolute
    /// deadline; this read is therefore non-destructive.
    /// # C: O(RESTART_ARGS)
    pub fn args(&self) -> [u64; RESTART_ARGS] {
        let mut out = [0u64; RESTART_ARGS];
        for (o, slot) in out.iter_mut().zip(self.args.iter()) { *o = slot.load(Ordering::Acquire); }
        out
    }
}

impl Default for RestartBlock {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_block_is_do_no_restart_syscall() {
        let b = RestartBlock::new();
        assert_eq!(b.kind(), RESTART_NONE);
        assert_eq!(b.args(), [0u64; RESTART_ARGS]);
    }

    #[test]
    fn arm_stores_kind_and_payload() {
        let b = RestartBlock::new();
        b.arm(RESTART_NANOSLEEP, [42, 0xdead_beef, 0, 0, 0, 0]);
        assert_eq!(b.kind(), RESTART_NANOSLEEP);
        assert_eq!(b.args()[0], 42);
        assert_eq!(b.args()[1], 0xdead_beef);
    }

    #[test]
    fn read_is_non_destructive_so_repeat_interrupts_resume_same_deadline() {
        let b = RestartBlock::new();
        b.arm(RESTART_NANOSLEEP, [9_000, 0, 0, 0, 0, 0]);
        assert_eq!(b.args()[0], 9_000);
        assert_eq!(b.args()[0], 9_000);
        assert_eq!(b.kind(), RESTART_NANOSLEEP);
    }

    #[test]
    fn disarm_returns_to_do_no_restart_syscall() {
        let b = RestartBlock::new();
        b.arm(RESTART_NANOSLEEP, [1, 2, 3, 4, 5, 6]);
        b.disarm();
        assert_eq!(b.kind(), RESTART_NONE);
    }
}
