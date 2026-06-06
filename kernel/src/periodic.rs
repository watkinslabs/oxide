//! Timer-driver kthread — the generic process-context driver for the
//! software timer wheel (`crates/kernel/timer`). Subsystems self-register
//! their OWN periodic work from their own init (net tcp-retransmit in
//! net::sock::init, sched cpu.max + load-balance in install_default_runqueue,
//! ARP GC on the virtio-net driver's probe, …) via `timer::register_periodic`.
//! This kthread only fires the due ones — no subsystem work is hardcoded
//! here. Process context, so callbacks may take runqueue/subsystem locks
//! (unlike the IRQ/softirq tick). docs/53 kernel = glue.
#![cfg(target_os = "oxide-kernel")]

use sched::live::WaitList;

static TIMER_WAIT: WaitList = WaitList::new();
const TICK_NS: u64 = 100_000_000; // driver granularity (per-timer intervals honored by run_due)

/// # C: O(due timers) per 100 ms wake
extern "C" fn timer_driver(_arg: usize) -> ! {
    loop {
        let now = syscalls::vvar::monotonic_now_ns();
        timer::run_due(now);
        // SAFETY: running kthread on this CPU; preempt-off; no lock held across the park; schedule() yields immediately after per the WaitList contract.
        unsafe {
            TIMER_WAIT.park_with_deadline(now + TICK_NS);
            sched::live::schedule();
        }
    }
}

/// Spawn the timer-driver kthread. Call once at boot after the runqueue is
/// installed; subsystems self-register their timers independently.
/// # C: O(1)
pub fn spawn() {
    let tid = sched::live::next_tid();
    // SAFETY: boot path after install_default_runqueue; entry is a 'static extern "C" fn ptr; arg unused.
    let _ = unsafe { sched::live::spawn_kernel_thread(tid, "ktimers", timer_driver, 0) };
}
