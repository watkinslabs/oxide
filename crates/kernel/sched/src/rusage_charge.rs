// The charge side of `struct rusage`. Every counter behind a `rusage` field
// has exactly one entry point here, and each one charges BOTH the per-task
// atomic (`RUSAGE_THREAD`, `/proc/<tid>/stat`) and its process-wide sibling
// (`RUSAGE_SELF`, `times(2)`) in the same call.
//
// Both charges are required because the two answer different questions and a
// thread's counters vanish with the thread: Linux walks the live threads and
// adds `signal_struct`'s residue for the dead ones, which needs the same event
// recorded in two places. Charging them together at the event — rather than
// deriving one from the other later — is what keeps them from drifting.
//
// Callers are the real event sites, never a syscall shim: the page-fault
// dispatcher, the block-layer submit path, and `__schedule`'s switch-out.

use crate::Task;

use core::sync::atomic::Ordering;

/// One resolved user page fault. `major` = the fault needed a read from the
/// backing store (Linux `VM_FAULT_MAJOR`); anything the page cache or a
/// zero-fill satisfied is minor. Feeds `ru_minflt`/`ru_majflt`.
/// # C: O(1)
/// # Ctx: fault
pub fn fault(t: &Task, major: bool) {
    if major { t.maj_flt.fetch_add(1, Ordering::Relaxed); }
    else     { t.min_flt.fetch_add(1, Ordering::Relaxed); }
    t.thread_group.group_acct().charge_fault(major);
}

/// Bytes this task caused to be read from a block device. Charged at SUBMIT,
/// to the submitting task — a completion runs in IRQ or worker context, where
/// the current task is unrelated to the one that asked for the I/O. Reported
/// as `ru_inblock` in 512-byte units. # C: O(1)
pub fn io_read(t: &Task, bytes: u64) {
    t.io_read_bytes.fetch_add(bytes, Ordering::Relaxed);
    t.thread_group.group_acct().charge_io_read(bytes);
}

/// Bytes this task caused to be written to a block device, charged at submit
/// for the same reason as [`io_read`]. Reported as `ru_oublock`. # C: O(1)
pub fn io_write(t: &Task, bytes: u64) {
    t.io_write_bytes.fetch_add(bytes, Ordering::Relaxed);
    t.thread_group.group_acct().charge_io_write(bytes);
}

/// One switch away from `t`. `voluntary` = it blocked and gave the CPU up
/// (`ru_nvcsw`); otherwise it was preempted while still runnable
/// (`ru_nivcsw`). # C: O(1)
/// # Ctx: scheduler, IRQ-off
pub fn ctxsw(t: &Task, voluntary: bool) {
    if voluntary { t.nvcsw.fetch_add(1, Ordering::Relaxed); }
    else         { t.nivcsw.fetch_add(1, Ordering::Relaxed); }
    t.thread_group.group_acct().charge_ctxsw(voluntary);
}

/// Latch a departing address space's resident-set peak onto the process, so an
/// `execve(2)` or a thread exit cannot lose it. Linux does this by keeping
/// `signal_struct::maxrss` alongside the live `mm->hiwater_rss`. # C: O(1)
pub fn latch_hiwater_rss(t: &Task, pages: u64) {
    t.thread_group.group_acct().raise_hiwater_rss(pages);
}
