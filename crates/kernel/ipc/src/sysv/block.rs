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

/// Publish the running task on `wl` — marks it Sleeping and pushes it onto the
/// list — WITHOUT yielding. MUST be called while the object lock is still held,
/// then the caller drops that lock and calls [`yield_and_classify`]. Splitting
/// the park this way is what closes the lost-wakeup window: a publisher must
/// take the object lock to mutate, so once the waiter has published under that
/// same lock, no commit can wake into an empty list.
///
/// # SAFETY: caller is the running task on this CPU in process context with the
/// runqueue installed and preemption disabled, and yields via
/// [`yield_and_classify`] immediately after dropping the object lock.
/// # C: O(N_waiters) dedup scan
/// # Ctx: process
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn publish_park(wl: &sched::live::WaitList, deadline_ns: u64) {
    // SAFETY: the documented caller contract for `publish_park` is exactly `WaitList::park_interruptible_with_deadline`'s: running task, preempt-off, runqueue installed, yield immediately after the object lock is dropped.
    unsafe { wl.park_interruptible_with_deadline(deadline_ns); }
}

/// # SAFETY: hosted stub; no scheduler exists, so nothing is parked.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub unsafe fn publish_park(_wl: &HostedWaitList, _deadline_ns: u64) {}

/// Drop the running task's registration from `wl` after a wake that did not
/// come from the list itself (signal, deadline). Without it the list keeps a
/// strong `Arc<Task>` until the next broadcast.
/// # C: O(N_waiters)
#[cfg(target_os = "oxide-kernel")]
pub fn unpublish_park(wl: &sched::live::WaitList) { wl.remove_current(); }

/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn unpublish_park(_wl: &HostedWaitList) {}

/// Yield after [`publish_park`], then classify why the task resumed.
/// `deadline_ns` of `0` means "no timeout".
///
/// # SAFETY: caller published itself via [`publish_park`] and has since dropped
/// every object lock; process context, runqueue installed, preemption disabled.
/// # C: O(1) plus the sleep
/// # Ctx: process
/// # Sleeps: yes
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn yield_and_classify(deadline_ns: u64) -> Wake {
    // SAFETY: process context with the runqueue installed and preemption disabled, as required by `schedule`; this is the yield the preceding `publish_park` expects.
    unsafe { sched::live::schedule(); }
    if deadline_ns != 0 && now_ns() >= deadline_ns { return Wake::TimedOut; }
    if signal_pending() { return Wake::Signal; }
    Wake::Retry
}

/// # SAFETY: hosted stub; no scheduler exists, so nothing was parked.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub unsafe fn yield_and_classify(_deadline_ns: u64) -> Wake { Wake::Signal }

/// Park on `wl` until woken, then classify the wake. `deadline_ns` of `0`
/// means "no timeout". For callers that publish and yield in one step because
/// they hold no object lock across the park; a caller holding one must use
/// [`publish_park`] + [`yield_and_classify`] around the drop instead.
///
/// # SAFETY: caller is the running task on this CPU in process context with
/// the runqueue installed and preemption disabled, holds no lock a waker also
/// needs, and yields immediately (this function is the yield).
/// # C: O(1) plus the sleep
/// # Ctx: process
/// # Sleeps: yes
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn park_until(wl: &sched::live::WaitList, deadline_ns: u64) -> Wake {
    // SAFETY: `park_until`'s contract is the union of `publish_park`'s and `yield_and_classify`'s, both of which are satisfied by this caller per the doc comment above.
    unsafe { publish_park(wl, deadline_ns); yield_and_classify(deadline_ns) }
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
