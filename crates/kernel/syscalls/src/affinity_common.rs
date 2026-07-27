// affinity shared helpers — one syscall, one file (docs/53 §0). Decision rules
// live in the hosted-testable `affinity_abi`; this file only resolves the
// target task and the live CPU set.

#![cfg(target_os = "oxide-kernel")]

/// Resolve the affinity target task as an `Arc`: `pid==0` → the calling
/// THREAD; else the task whose vpid is `pid` in the CALLER's pid namespace
/// (Linux `find_process_by_pid` → `find_task_by_vpid`, which resolves a tid,
/// not a thread-group id). None → ESRCH.
/// # C: O(1) registry lookup
pub(crate) fn affinity_target(pid: u32) -> Option<alloc::sync::Arc<sched::Task>> {
    if pid == 0 {
        let t = sched::live::current()?.tid;
        sched::live::registry::lookup(t)
    } else {
        sched::live::registry::resolve_user_pid(pid)
    }
}

/// Linux `cpu_active_mask` — the CPUs a task may actually be placed on. Read
/// from the authoritative online BITMAP (`cpu::smp::online_mask`), not the
/// online COUNT: a count assumes ids are dense `0..n`, which mis-reports
/// affinity the moment a CPU id is skipped. The boot CPU is always active, so
/// an empty bitmap (before `set_boot_cpu_id`) still yields a schedulable mask
/// rather than turning every `sched_setaffinity` into EINVAL.
/// # C: O(1)
pub(crate) fn active_cpu_mask() -> u64 {
    let m = cpu::smp::online_mask();
    if m == 0 { 1 } else { m }
}
