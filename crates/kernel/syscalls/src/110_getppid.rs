// 110 getppid — one syscall, one file (docs/53 §0).

use core::sync::atomic::Ordering;
use syscall::SyscallArgs;

/// `sys_getppid()` — slot 110. PID-namespace aware: in a non-init pid_ns the
/// parent is visible only if it shares the namespace (else Linux reports 0).
/// # C: O(1) init-ns; O(1) registry lookup otherwise
pub fn sys_getppid(_args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    // parent_tid is the parent's INTERNAL tid (kernel linkage); getppid must
    // report the parent's VPID (vtgid), never the opaque internal id.
    let ppid = cur.parent_tid.load(Ordering::Acquire);
    let cur_ns = cur.pid_ns.load(Ordering::Acquire);
    match sched::live::registry::lookup(ppid) {
        // Init ns: report the parent's vpid (fall back to the internal tid
        // only for a parent that never got a vpid stamped, e.g. a kthread).
        Some(p) if cur_ns == 0 => {
            let v = p.vtgid.load(Ordering::Acquire);
            if v != 0 { v as i64 } else { ppid as i64 }
        }
        // F105: in a non-init pid_ns, parent visible only if it shares the NS.
        Some(p) if p.pid_ns.load(Ordering::Acquire) == cur_ns => {
            let v = p.vtgid.load(Ordering::Acquire);
            if v != 0 { v as i64 } else { p.tgid.load(Ordering::Acquire) as i64 }
        }
        _ => 0, // no parent / not visible from our NS — Linux reports 0.
    }
}
