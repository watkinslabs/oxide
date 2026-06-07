// affinity shared helpers — one syscall, one file (docs/53 §0). Moved verbatim from affinity.rs.

#![cfg(target_os = "oxide-kernel")]

/// Resolve the affinity target task as an `Arc`: `pid==0` → current; else
/// the task with that global tid. None → ESRCH.
/// # C: O(1) registry lookup
pub(crate) fn affinity_target(pid: u32) -> Option<alloc::sync::Arc<sched::Task>> {
    let tid = if pid == 0 { sched::live::current()?.tid } else { pid };
    sched::live::registry::lookup(tid)
}

/// Bitmask of online CPUs (bit N set ⇔ CPU N online). Capped at 64.
/// # C: O(1)
pub(crate) fn online_cpu_mask() -> u64 {
    let n = (cpu::smp::online_count() as u32).min(64);
    if n >= 64 { u64::MAX } else { (1u64 << n) - 1 }
}
