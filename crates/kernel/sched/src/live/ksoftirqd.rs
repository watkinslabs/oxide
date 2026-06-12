//! `ksoftirqd` — softirq bottom-half kthread, per Linux `kernel/softirq.c`
//! (`run_ksoftirqd` / `wakeup_softirqd`). Drains softirqs in PROCESS context
//! when the IRQ-tail restart gate (`softirq::run_pending`) defers under load
//! — e.g. a virtio-net RX flood that re-arms `Slot::NetRx` on every MSI. The
//! IRQ-tail drain (lapic/gic timer + MSI tails) still runs every tick; this is
//! the schedulable, preemptible drainer the gate hands the remainder to, so a
//! flood can't monopolise a CPU.
//!
//! oxide has ONE global softirq pending mask drained under a single
//! `IN_PROGRESS` guard (not Linux's per-CPU masks), so one ksoftirqd thread
//! mirrors that model; the guard serialises it against the IRQ-tail drainer.
use super::WaitList;

/// ksoftirqd parks here; `wake()` (the softirq `wakeup_softirqd` hook) rouses it.
static WAIT: WaitList = WaitList::new();
/// Missed-wakeup safety net. The wake site (`wakeup_softirqd`) can fire in the
/// window between our `pending()` check and `park()`, and `try_to_wake_up`
/// can't self-wake a still-running task (it spins on `on_cpu`). A deadline
/// re-check closes that race — same idiom as `ktimers`. The IRQ-tail drainer
/// keeps `PENDING` moving meanwhile, so this is a backstop, not the latency path.
const BACKSTOP_NS: u64 = 100_000_000;

#[cfg(target_arch = "x86_64")]
fn now_ns() -> u64 { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
#[cfg(target_arch = "aarch64")]
fn now_ns() -> u64 { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }

/// Linux `run_ksoftirqd`: drain while pending, yielding between passes so a
/// sustained flood stays preemptible (`cond_resched`), then park until woken.
/// # C: O(pending softirq work) per wake
extern "C" fn ksoftirqd(_arg: usize) -> ! {
    loop {
        if softirq::pending() {
            // SAFETY: process-context kthread with IRQs enabled (run_pending's
            // documented contract); the global IN_PROGRESS guard serialises
            // this against the IRQ-tail drainer; no lock held across the call.
            unsafe { softirq::run_pending(); }
            // cond_resched(): yield so draining a flood can't starve other
            // tasks. schedule() re-enqueues this still-Runnable task.
            // SAFETY: running kthread, preempt-off, no lock held.
            unsafe { super::schedule(); }
            continue;
        }
        // Idle — park until `wake()` (or the deadline backstop) rouses us.
        // SAFETY: running kthread on this CPU; preempt-off; no lock held across
        // the park; schedule() yields immediately per the WaitList contract.
        unsafe { WAIT.park_with_deadline(now_ns() + BACKSTOP_NS); super::schedule(); }
    }
}

/// Linux `wakeup_softirqd` — installed as the softirq crate's deferral hook.
/// Rouse ksoftirqd to finish a deferred drain in process context. A no-op
/// when ksoftirqd itself is the caller (it isn't parked, so the list is empty).
/// # C: O(1)
fn wake() { WAIT.wake_one(); }

/// Spawn ksoftirqd and install the `wakeup_softirqd` hook. Boot, once, after
/// the runqueue installs (same site as `spawn_timer_driver`).
/// # C: O(1)
pub fn spawn_ksoftirqd() {
    softirq::set_wakeup_hook(wake);
    let tid = super::next_tid();
    // SAFETY: boot path after install_default_runqueue; entry is a 'static extern "C" fn ptr; arg unused.
    let _ = unsafe { super::spawn_kernel_thread(tid, "ksoftirqd", ksoftirqd, 0) };
}
