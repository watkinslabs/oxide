// 153 vhangup — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_vhangup` — slot 153. Linux: revoke access to the calling task's
/// controlling terminal by posting SIGHUP to every task in the same
/// session. Privileged (CAP_SYS_TTY_CONFIG / root).
/// # C: O(N_tasks)
pub fn sys_vhangup(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    if !cur.has_cap(sched::cap::SYS_TTY_CONFIG) { return -(Errno::Eperm.as_i32() as i64); }
    let sid = cur.sid();
    for tid in sched::live::registry::live_tids() {
        if let Some(t) = sched::live::registry::lookup(tid) {
            if t.sid() == sid {
                t.sigpending.fetch_or(sched::Signum::Sighup.bit(), Ordering::Release);
                sched::live::signal_wake_up(&t);
            }
        }
    }
    0
}
