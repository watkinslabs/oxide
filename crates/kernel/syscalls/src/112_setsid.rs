// 112 setsid — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_setsid()` — slot 112. Makes the caller a session leader:
/// new sid = new pgid = tid. Returns the new sid.
/// # C: O(1)
pub fn sys_setsid(_args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let cur = match sched::live::current() { Some(c) => c, None => return 1 };
    let vpid = cur.vtgid.load(Ordering::Acquire);
    let id = if vpid != 0 { vpid } else { cur.tid };
    cur.sid.store(id, Ordering::Release);
    cur.pgid.store(id, Ordering::Release);
    // F200: setsid(2) detaches the session leader from any
    // controlling terminal it inherited.
    // SAFETY: single-mutator per `13§5` — running task on this CPU.
    unsafe { *cur.ctty.get() = None; }
    id as i64
}
