// The sleeping half of the notification protocol, and the hosted stand-in for
// it. Every rule about WHAT to wait for is in `state.rs`; this file only
// parks and wakes.
//
// The live wait queue exists only under the scheduler, so the hosted suite
// gets a stand-in whose park is never reached: hosted tests drive the queue
// transitions directly, exactly as the FUSE channel's do.

#[cfg(target_os = "oxide-kernel")]
pub use sched::live::wait_list::WaitList;

/// Hosted stand-in; see the file comment.
#[cfg(not(target_os = "oxide-kernel"))]
pub struct WaitList;

#[cfg(not(target_os = "oxide-kernel"))]
impl WaitList {
    /// # C: O(1)
    pub const fn new() -> Self { Self }
    /// # C: O(1)
    pub fn wake_all(&self) {}
}

/// Why a wait ended.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Woke {
    /// The condition the caller was waiting for now holds.
    Ready,
    /// A signal the task must act on arrived first.
    Interrupted,
}

/// Sleep until `cond` holds or a signal arrives. `killable` narrows that to a
/// FATAL signal, which is what a filter installed with
/// `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` asks for once its notification has
/// reached a supervisor: an ordinary signal must not pull the task out from
/// under a supervisor that is already acting on it.
///
/// # SAFETY: process context on the running task's own CPU with the runqueue
/// installed, holding no lock a waker of `wq` takes.
/// # Ctx: process
/// # Sleeps: yes
/// # C: O(N_wakeups)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn wait_until(wq: &WaitList, killable: bool, cond: impl FnMut() -> bool) -> Woke {
    use sched::WaitOutcome;
    // SAFETY: forwarded fn-level contract — sleepable context, `wq` outlives
    // the wait, and the caller drops the listener lock before parking.
    let out = unsafe {
        if killable { sched::live::wait_event_killable(wq, cond) }
        else { sched::live::wait_event_interruptible(wq, cond) }
    };
    match out { WaitOutcome::Ready => Woke::Ready, _ => Woke::Interrupted }
}

/// Hosted stand-in: nothing sleeps, so an unmet condition is reported as an
/// interruption rather than looping forever.
/// # SAFETY: never parks; see the live variant for the real contract.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub unsafe fn wait_until(_wq: &WaitList, _killable: bool, mut cond: impl FnMut() -> bool) -> Woke {
    if cond() { Woke::Ready } else { Woke::Interrupted }
}
