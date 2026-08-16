//! Suspend-to-idle blocking, the scheduler side of `32a§8`.
//!
//! The state machine — the three-valued state and the check-and-commit under
//! one lock — is `power::suspend::s2idle`. This supplies the two primitives it
//! cannot have: a task that blocks until the state says woken, and the kick
//! that pushes every CPU through its idle decision. Both are installed as
//! hooks, because `power` sits below the scheduler in the crate graph.

use alloc::sync::Arc;

use sched::live::WaitList;

use super::s2idle::{self, S2idleState};

fn wait_list() -> Arc<WaitList> {
    static LIST: sync::Spinlock<Option<Arc<WaitList>>, sync::TaskList> =
        sync::Spinlock::new(None);
    let mut slot = LIST.lock();
    slot.get_or_insert_with(|| Arc::new(WaitList::new())).clone()
}

/// Block the calling task until a wakeup sets the s2idle state to woken.
///
/// Uninterruptible on purpose: a signal must not end a suspend-to-idle. The
/// only thing that resumes the machine is a wakeup event, and a task returning
/// from here on a signal would leave the devices suspended.
/// # C: O(1) plus the sleep
/// # Sleeps: yes
pub fn wait() {
    let list = wait_list();
    // SAFETY: process context on the task driving the suspend, no runqueue or
    // device-model lock held; the wait list outlives the wait via the Arc.
    unsafe { sched::live::wait_event_uninterruptible(&list, || s2idle::state() == S2idleState::Wake); }
}

/// Release the task blocked in [`wait`]. Safe from interrupt context.
/// # C: O(N_waiters)
pub fn wake() { wait_list().wake_all(); }

/// Push every CPU through its idle decision, so each re-reads the s2idle state
/// and each restarts its timers on the way out.
/// # C: O(N_cpus)
pub fn kick_idle_cpus() {
    for cpu in 0..(cpu::MAX_CPUS as u32) { sched::live::resched_curr(cpu); }
}

/// Install these primitives into the suspend core. `kmain` calls this once.
/// # C: O(1)
pub fn init() { s2idle::set_hooks(wait, wake, kick_idle_cpus); }
