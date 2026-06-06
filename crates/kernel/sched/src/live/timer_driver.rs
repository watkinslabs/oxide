//! Generic timer-wheel driver kthread (`ktimers`). Fires due software
//! timers (`crates/kernel/timer`) in process context — so callbacks may
//! take runqueue/subsystem locks. Subsystems self-register their own work
//! (docs/56); this driver names none. Lives in sched because it needs the
//! kthread spawn + park + monotonic clock the scheduler owns.
use super::WaitList;

static WAIT: WaitList = WaitList::new();
const TICK_NS: u64 = 100_000_000;

#[cfg(target_arch = "x86_64")]
fn now_ns() -> u64 { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
#[cfg(target_arch = "aarch64")]
fn now_ns() -> u64 { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }

/// # C: O(due timers) per 100 ms wake
extern "C" fn driver(_arg: usize) -> ! {
    loop {
        let now = now_ns();
        timer::run_due(now);
        // SAFETY: running kthread on this CPU; preempt-off; no lock held across the park; schedule() yields immediately after per the WaitList contract.
        unsafe { WAIT.park_with_deadline(now + TICK_NS); super::schedule(); }
    }
}

/// Spawn the timer-driver kthread. Boot, once, after the runqueue installs.
/// # C: O(1)
pub fn spawn_timer_driver() {
    let tid = super::next_tid();
    // SAFETY: boot path after install_default_runqueue; entry is a 'static extern "C" fn ptr; arg unused.
    let _ = unsafe { super::spawn_kernel_thread(tid, "ktimers", driver, 0) };
}
