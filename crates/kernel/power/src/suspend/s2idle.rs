// Suspend-to-idle per `32a§8`.
//
// The lock matters more than the code it guards: the pending-wakeup check and
// the store that says "entered" must be one critical section, or a wakeup
// landing between them finds the state still `None`, declines to post a wake,
// and leaves the machine blocked with nothing left to wake it.
//
// The blocking itself belongs to the scheduler, which is above this crate, so
// it arrives as an installed hook — the same indirection
// `machine::set_driver_shutdown_hook` uses.

use sync::{Spinlock, TaskList as PowerListClass};

use super::ops::PlatformS2idleOps;

/// Where the machine is in a suspend-to-idle cycle.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum S2idleState {
    /// Not in a cycle, or the cycle has ended.
    None,
    /// Committed: every CPU is heading for its idle instruction.
    Enter,
    /// A wakeup landed; the waiter may proceed.
    Wake,
}

/// Blocks the calling task until [`S2idleState::Wake`] is stored, then returns.
pub type WaitHook = fn();
/// Releases every task blocked in [`WaitHook`].
pub type WakeHook = fn();
/// Kicks every CPU so it re-evaluates its idle decision.
pub type KickIdleHook = fn();

struct Hooks { wait: Option<WaitHook>, wake: Option<WakeHook>, kick: Option<KickIdleHook> }

static STATE: Spinlock<S2idleState, PowerListClass> = Spinlock::new(S2idleState::None);
static HOOKS: Spinlock<Hooks, PowerListClass> =
    Spinlock::new(Hooks { wait: None, wake: None, kick: None });

/// Install the scheduler-side blocking primitives. `kmain` wires these once.
/// # C: O(1)
pub fn set_hooks(wait: WaitHook, wake: WakeHook, kick: KickIdleHook) {
    let mut h = HOOKS.lock();
    h.wait = Some(wait); h.wake = Some(wake); h.kick = Some(kick);
}

/// Current cycle state. # C: O(1)
pub fn state() -> S2idleState { *STATE.lock() }

/// Open a cycle. # C: O(1)
pub fn s2idle_begin() { *STATE.lock() = S2idleState::None; }

/// What [`s2idle_enter`] does given the pending-wakeup answer read under the
/// lock: either commit to blocking, or fall straight back out.
///
/// Split out so the decision is checkable without a scheduler; the ordering
/// this encodes — check and commit under one lock — is the whole contract.
/// # C: O(1)
pub fn enter_decision(pending: bool) -> S2idleState {
    if pending { S2idleState::None } else { S2idleState::Enter }
}

/// Whether a wake posted while the machine is in `state` must be recorded.
/// A wake arriving outside a cycle has nothing to release and is dropped;
/// anything inside one must land, including a second wake after the first.
/// # C: O(1)
pub fn wake_takes_effect(state: S2idleState) -> bool { state != S2idleState::None }

/// One pass of the idle wait: commit under the lock, park, then close out.
/// Returns without parking when a wakeup is already pending.
/// # C: O(1) plus the park
pub fn s2idle_enter() {
    {
        let mut s = STATE.lock();
        *s = enter_decision(super::wakeup::pm_wakeup_pending());
        if *s == S2idleState::None { return; }
    }
    kick_idle_cpus();
    if let Some(w) = HOOKS.lock().wait { w(); }
    // Every CPU restarts its timers and re-reads the clock on the way out.
    kick_idle_cpus();
    *STATE.lock() = S2idleState::None;
}

/// Record a wakeup and release the waiter. Safe from interrupt context.
/// # C: O(1)
pub fn s2idle_wake() {
    let wake = {
        let mut s = STATE.lock();
        if !wake_takes_effect(*s) { return; }
        *s = S2idleState::Wake;
        HOOKS.lock().wake
    };
    if let Some(w) = wake { w(); }
}

fn kick_idle_cpus() { if let Some(k) = HOOKS.lock().kick { k(); } }

/// Whether the suspend-to-idle loop breaks this time round, given the platform
/// table. A platform `wake` hook replaces the generic check entirely — it is
/// the platform's answer to "did anything wake us", and the reference does not
/// second-guess it.
/// # C: O(1)
pub fn loop_breaks(ops: Option<&PlatformS2idleOps>, pending: bool) -> bool {
    match ops.and_then(|o| o.wake) { Some(f) => f(), None => pending }
}

/// The suspend-to-idle loop: block in idle until something wakes the machine.
/// # C: O(wakeups)
pub fn s2idle_loop() {
    let ops = super::ops::s2idle_ops();
    loop {
        if loop_breaks(ops, super::wakeup::pm_wakeup_pending()) { return; }
        if let Some(c) = ops.and_then(|o| o.check) { c(); }
        s2idle_enter();
    }
}

#[cfg(test)]
#[path = "s2idle/tests.rs"]
mod tests;
