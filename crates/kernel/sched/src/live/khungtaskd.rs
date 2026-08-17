//! The hung-task watchdog kthread — the reference's `khungtaskd`.
//!
//! Policy is [`crate::hung_task`] and is proved hosted; this file is the loop
//! that applies it. Every `hung_task_timeout_secs` it walks the task registry
//! and reports each task that has sat in an uninterruptible sleep across the
//! whole window without one context switch. The report carries the park site
//! ([`crate::park_site`]) — the file:line of the sleep — which is the datum
//! that turns "the boot stopped" into "the boot stopped in THIS wait".
//!
//! Without it a wedge is only visible to whoever is watching the console at
//! the time, and only if they think to ask for a task dump.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use crate::hung_task::{self, Observation, Verdict};
use crate::live::WaitList;
use crate::Task;

/// Park slot for the scan loop's interval sleep. Nothing wakes it — the
/// deadline is the whole mechanism — but a `WaitList` is how this kernel
/// expresses a timed sleep.
static WAIT: WaitList = WaitList::new();

/// Longest one scan interval may be, so a `hung_task_timeout_secs` raised to
/// hours still lets the loop notice a lowered value. Mirrors the reference's
/// `hung_task_check_interval_secs` clamp to the timeout.
const MAX_INTERVAL_SECS: u64 = 120;
/// Interval used while the detector is disabled (`timeout_secs == 0`), so the
/// loop can pick a re-enable up rather than sleeping forever.
const DISABLED_POLL_SECS: u64 = 30;
const NS_PER_SEC: u64 = 1_000_000_000;

/// One pass over every live task. Returns how many were reported.
/// # C: O(N_tasks)
fn scan(now_ns: u64, timeout_secs: u64) -> usize {
    // `try_snapshot`: a scan that waited for the registry lock could itself be
    // the thing holding the machine up. A missed pass costs one interval.
    let Some(tasks) = crate::registry::try_snapshot() else { return 0 };
    let mut reported = 0usize;
    for t in tasks.iter() {
        let switch_count = t.nvcsw.load(Ordering::Relaxed)
            .wrapping_add(t.nivcsw.load(Ordering::Relaxed));
        let o = Observation {
            state: t.state(),
            wait: t.sleep_wait_state(),
            switch_count,
            last_switch_count: t.hung_last_switch_count.load(Ordering::Relaxed),
            last_switch_ns: t.hung_last_switch_ns.load(Ordering::Relaxed),
            now_ns,
        };
        match hung_task::classify(o, timeout_secs) {
            Verdict::Skip => {
                // A task that left the uninterruptible state must not carry a
                // stale window into its next sleep, or the first scan after it
                // blocks again would report it immediately.
                if o.last_switch_count != switch_count {
                    t.hung_last_switch_count.store(switch_count, Ordering::Relaxed);
                    t.hung_last_switch_ns.store(now_ns, Ordering::Relaxed);
                }
            }
            Verdict::Progressed => {
                t.hung_last_switch_count.store(switch_count, Ordering::Relaxed);
                t.hung_last_switch_ns.store(now_ns, Ordering::Relaxed);
            }
            Verdict::Hung => {
                reported += 1;
                if hung_task::claim_report() { report(t, now_ns); }
            }
        }
    }
    reported
}

/// The reference's `INFO: task <comm>:<pid> blocked for more than N seconds.`,
/// plus the park site this kernel can name where the reference would unwind a
/// stack. # C: O(comm + path length)
fn report(t: &Task, now_ns: u64) {
    let blocked_ns = now_ns.saturating_sub(t.hung_last_switch_ns.load(Ordering::Relaxed));
    klog::write_raw(b"INFO: task ");
    klog::write_raw(t.comm_irq_safe().as_bytes());
    klog::write_raw(b":");
    klog::write_dec_u64(u64::from(t.visible_pid()));
    klog::write_raw(b" blocked for more than ");
    klog::write_dec_u64(blocked_ns / NS_PER_SEC);
    klog::write_raw(b" seconds.\n      tid=");
    klog::write_dec_u64(t.tid as u64);
    klog::write_raw(b" last-syscall-nr=");
    klog::write_dec_u64(t.last_syscall_nr.load(Ordering::Relaxed) as u64);
    match t.park_site.get() {
        Some(site) => {
            klog::write_raw(b" wchan=");
            klog::write_raw(site.file().as_bytes());
            klog::write_raw(b":");
            klog::write_dec_u64(site.line() as u64);
        }
        // A blocked task with no recorded site is a hole in the park-site
        // coverage, and saying so is the only way that hole is ever found.
        None => klog::write_raw(b" wchan=<unrecorded>"),
    }
    klog::write_raw(b"\n");
}

/// Interval between scans: the reference clamps its check interval to the
/// timeout, so a short timeout is not sampled at a long period.
/// # C: O(1)
fn interval_secs(timeout_secs: u64) -> u64 {
    if timeout_secs == 0 { return DISABLED_POLL_SECS; }
    if timeout_secs < MAX_INTERVAL_SECS { timeout_secs } else { MAX_INTERVAL_SECS }
}

extern "C" fn khungtaskd(_arg: usize) -> ! {
    loop {
        let timeout = hung_task::timeout_secs();
        let now = timekeeper::monotonic_ns();
        let any = if timeout == 0 { 0 } else { scan(now, timeout) };
        if any != 0 && hung_task::panic_on_hung() {
            hal::kassert!(false, "hung_task: blocked tasks");
        }
        let deadline = timekeeper::monotonic_ns()
            .saturating_add(interval_secs(timeout).saturating_mul(NS_PER_SEC));
        // SAFETY: schedulable kthread in process context holding no subsystem
        // lock; the registry snapshot was released above.
        unsafe { WAIT.park_with_deadline(deadline); }
        // SAFETY: published on WAIT with a deadline; nothing else is held.
        unsafe { crate::live::schedule(); }
    }
}

/// Start the detector once the runqueue exists. One worker: the task list it
/// walks is machine-wide.
/// # C: O(1)
pub fn spawn_khungtaskd() -> Result<(), crate::live::SpawnError> {
    let tid = crate::live::next_tid();
    // SAFETY: called from kernel init after runqueue installation; the entry
    // is a static fn and takes no argument-owned memory.
    unsafe { crate::live::spawn_kernel_thread(tid, "khungtaskd", khungtaskd, 0) }.map(|_| ())
}
