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
    let Some(namespace) = cur.namespace_owner(namespace_identity::NamespaceKind::Pid) else {
        return 0;
    };
    let Some(parent) = sched::live::registry::lookup(ppid) else { return 0 };
    let leader_tid = parent.tgid.load(Ordering::Acquire);
    sched::live::registry::lookup(leader_tid)
        .and_then(|leader| leader.pid.visible_tid(&namespace)).unwrap_or(0) as i64
}
