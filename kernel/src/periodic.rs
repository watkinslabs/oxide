//! Process-context periodic system ticks (kernel glue).
//!
//! F152 retired the virtio-net rx kthread, which had also been the sole
//! driver of the ~100 ms periodic maintenance ticks. `tick_poll_combined`
//! runs in timer-IRQ context and must not take the runqueue / cgroup
//! locks these need, so they run here in a parked kthread (process
//! context), woken every 100 ms by `tick_wake_expired` (which fires from
//! the timer tick). `park_with_deadline` dedups on re-park, so the loop
//! never leaks WaitList entries.
#![cfg(target_os = "oxide-kernel")]

use sched::live::WaitList;

static PERIODIC_WAIT: WaitList = WaitList::new();
const PERIOD_NS: u64 = 100_000_000;

/// # C: O(cgroups + conns + cpus) per 100 ms wake
extern "C" fn periodic_kthread(_arg: usize) -> ! {
    loop {
        let now = syscalls::vvar::monotonic_now_ns();
        // TCP retransmit / RTO + connection-abort timers (RFC 6298).
        net::sock::stack().tcp_retx_tick(now);
        // cgroup v2 cpu.max: throttle over-quota cgroups, refill on period (`26`).
        sched::cgroup::tick(now);
        // SMP load balance per `13§11` (no-op with <2 CPUs).
        for _ in 0..cpu::smp::online_count() {
            // SAFETY: kthread (process) context, not under any runqueue lock; balance_once takes the per-CPU inner locks in cpu-id order so no pair deadlocks.
            if unsafe { sched::live::balance::balance_once() } == 0 { break; }
        }
        // ARP neighbor GC (stale entries older than 60 s).
        drv_virtio_net::modern::arp_cache().gc(now);
        // Park until the next period; woken by tick_wake_expired.
        // SAFETY: running kthread on this CPU; preempt-off; no lock held across the park; schedule() yields immediately after per the WaitList contract.
        unsafe {
            PERIODIC_WAIT.park_with_deadline(now + PERIOD_NS);
            sched::live::schedule();
        }
    }
}

/// Spawn the periodic-tick kthread. Call once at boot after the runqueue
/// is installed.
/// # C: O(1)
pub fn spawn() {
    let tid = sched::live::next_tid();
    // SAFETY: boot path after install_default_runqueue; entry is a 'static extern "C" fn ptr; arg unused.
    let _ = unsafe { sched::live::spawn_kernel_thread(tid, "kperiodic", periodic_kthread, 0) };
}
