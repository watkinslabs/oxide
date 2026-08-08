// Sleeping half of a delegation break (`vfs::file::deleg` owns the decision;
// this owns the wait, because the scheduler and the clock live on this side —
// the same split as the conflicting-open lease wait in `open_common`).

/// Wait for every delegation on `inode` to be released, or force-break them
/// once the break time has elapsed. `true` = the way is clear, `false` = a
/// deliverable signal arrived first and the mutation must report `EINTR`.
///
/// Yields the CPU like a blocking record lock rather than parking, because the
/// event being waited for is a holder answering in USERSPACE, which no kernel
/// wakeup covers. # C: sleeps up to the break time
fn deleg_break_wait(inode: &vfs::InodeRef) -> bool {
    let flavour = vfs::file::FL_DELEG;
    let Some(cur) = sched::live::current() else {
        vfs::file::lease_force_break(inode, flavour, true);
        return true;
    };
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")] let now = || hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")] let now = || hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let deadline = now().saturating_add(vfs::file::LEASE_BREAK_NS);
    while vfs::file::lease_conflict(inode, flavour, true) {
        if sched::live::sigpend::deliverable_signals(cur) != 0 { return false; }
        if now() >= deadline {
            vfs::file::lease_force_break(inode, flavour, true);
            break;
        }
        // SAFETY: process ctx; preempt-off; runqueue installed; voluntary schedule() yields the CPU; we stay Runnable so the scheduler reselects us.
        unsafe { sched::live::schedule::schedule(); }
    }
    true
}

/// Install the wait so every VFS mutation path can complete a delegation
/// break. # C: O(1)
pub fn init() { vfs::file::set_deleg_wait_hook(deleg_break_wait); }

/// Break every delegation standing in the way of a mutation of `inode`, as the
/// mutation syscalls' one-line gate. `Some(neg_errno)` fails the syscall (only
/// `EINTR` is possible); `None` lets it proceed. # C: O(1) with no delegation
pub(crate) fn break_deleg_for_mutation(inode: &vfs::InodeRef) -> Option<i64> {
    match vfs::file::break_deleg(inode) {
        Ok(())  => None,
        Err(e)  => Some(-(e as i64)),
    }
}
