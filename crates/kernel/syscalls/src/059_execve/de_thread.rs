use syscall::errno::Errno;

/// Kill every exec sibling and wait until each has retired from its CPU.
/// # C: O(N_threads + N_wakeups)
pub(super) fn run(cur: &sched::Task) -> Result<(), Errno> {
    sched::live::zap_other_threads();
    // SAFETY: execve runs in process context with no scheduler lock held; the
    // thread group's wait list outlives this task and every sibling exit.
    crate::exec_drain::result(unsafe { cur.thread_group.wait_exec_siblings() })
}
