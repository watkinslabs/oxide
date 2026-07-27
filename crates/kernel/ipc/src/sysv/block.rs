//! The sleep half of the blocking SysV operations (`semop`, `msgsnd`,
//! `msgrcv`). Both classes need identical behaviour — park interruptibly with
//! an optional absolute deadline, then classify the wake as real / timed-out /
//! signalled — so the sequencing lives here once.
//!
//! Off the kernel target there is no runqueue to park on. Hosted builds
//! therefore expose the same API with `park_until` reporting [`Wake::Signal`],
//! which makes the callers' retry loops terminate instead of spinning; hosted
//! tests exercise the decision functions directly and never reach a park.

/// Why a parked SysV waiter resumed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Wake {
    /// A publisher woke us, or the wake was spurious: re-evaluate.
    Retry,
    /// The absolute deadline passed without the operation becoming possible.
    TimedOut,
    /// A deliverable signal is pending; unwind with `EINTR`.
    Signal,
}

/// Current CLOCK_MONOTONIC reading in nanoseconds, for turning a relative
/// `semtimedop` timeout into the absolute deadline the park scanner wants.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    now
}

/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn now_ns() -> u64 { 0 }

/// Whether the running task has a signal that would be delivered on return to
/// userspace — Linux `signal_pending(current)`. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn signal_pending() -> bool { sched::live::deliverable_signals_self() != 0 }

/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn signal_pending() -> bool { false }

/// Park on `wl` until woken, then classify the wake. `deadline_ns` of `0`
/// means "no timeout". The caller MUST have published itself into the
/// object's pending state and dropped the object lock in the same critical
/// section that this call is made from, exactly as Linux drops `sem_lock`
/// between `__set_current_state` and `schedule()`.
///
/// # SAFETY: caller is the running task on this CPU in process context with
/// the runqueue installed and preemption disabled, holds no lock a waker also
/// needs, and yields immediately (this function is the yield).
/// # C: O(1) plus the sleep
/// # Ctx: process
/// # Sleeps: yes
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn park_until(wl: &sched::live::WaitList, deadline_ns: u64) -> Wake {
    // SAFETY: the documented caller contract for this function is exactly `WaitList::park_interruptible_with_deadline`'s: running task, preempt-off, runqueue installed, no waker-visible lock held, immediate yield below.
    unsafe { wl.park_interruptible_with_deadline(deadline_ns); }
    // SAFETY: process context with the runqueue installed and preemption disabled, as required by `schedule`; this is the yield the park above expects.
    unsafe { sched::live::schedule(); }
    if deadline_ns != 0 && now_ns() >= deadline_ns { return Wake::TimedOut; }
    if signal_pending() { return Wake::Signal; }
    Wake::Retry
}

/// # SAFETY: hosted stub; no scheduler exists, so nothing is parked.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub unsafe fn park_until(_wl: &HostedWaitList, _deadline_ns: u64) -> Wake { Wake::Signal }

/// Stand-in for `sched::live::WaitList`, which is kernel-only. Hosted builds
/// need the field to exist so the object structs compile for unit tests; no
/// hosted test parks, so the list never holds anything.
#[cfg(not(target_os = "oxide-kernel"))]
pub struct HostedWaitList;

#[cfg(not(target_os = "oxide-kernel"))]
impl HostedWaitList {
    /// # C: O(1)
    pub const fn new() -> Self { Self }
    /// # C: O(1)
    pub fn wake_one(&self) {}
    /// # C: O(1)
    pub fn wake_all(&self) {}
}

/// The wait-list type in use for this build.
#[cfg(target_os = "oxide-kernel")]
pub type WaitList = sched::live::WaitList;
/// The wait-list type in use for this build.
#[cfg(not(target_os = "oxide-kernel"))]
pub type WaitList = HostedWaitList;

/// Thread-group id of the calling process — Linux stamps `sempid` / `q_lspid`
/// / `q_lrpid` with `task_tgid(current)`, not the thread id. # C: O(1)
pub fn current_tgid() -> u32 {
    match sched::current() {
        Some(t) => {
            let v = t.vtgid.load(core::sync::atomic::Ordering::Acquire);
            if v != 0 { v } else { t.tgid.load(core::sync::atomic::Ordering::Acquire) }
        }
        None => 0,
    }
}

/// Wall-clock seconds for the `*_otime` / `*_ctime` stat fields
/// (`ktime_get_real_seconds`). # C: O(1)
pub fn real_seconds() -> i64 { (timekeeper::realtime_ns() / 1_000_000_000) as i64 }
