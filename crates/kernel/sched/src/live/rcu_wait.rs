//! Scheduler-owned wait bridge for blocking RCU grace-period callers.

use super::WaitList;

static RCU_WAIT: WaitList = WaitList::new();

/// Install the dependency-inverted RCU wait bridge after the runqueue exists.
/// # C: O(1)
pub fn install() { sync::set_wait_hooks(wait_for_progress, wake); }

fn wait_for_progress(epoch: u64) {
    // SAFETY: synchronize_rcu and rcu_barrier run only in process context and
    // retain no sync drain or callback lock while this generic predicate waits.
    unsafe {
        let _ = super::wait_event_uninterruptible(&RCU_WAIT,
            || sync::wait_epoch() != epoch);
    }
}

fn wake() { RCU_WAIT.wake_all(); }
