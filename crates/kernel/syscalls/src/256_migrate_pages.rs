// 256 migrate_pages — `SYSCALL_DEFINE4(migrate_pages)` / `kernel_migrate_pages`
//. ABI shim (docs/53).

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::SyscallArgs;
use vmm::mempolicy::nodes_with_memory;

use crate::misc::mempolicy_common::{cap_sys_nice, err, read_nodemask};

/// `migrate_pages(pid, maxnode, old_nodes, new_nodes)`.
///
/// Errno order: unreadable/illegal `old_nodes` then `new_nodes` (EFAULT /
/// EINVAL) → unknown pid (ESRCH) → `ptrace_may_access` (EPERM) → a
/// destination node outside the target's cpuset without CAP_SYS_NICE (EPERM)
/// → a destination set that intersects the caller's cpuset emptily (EINVAL).
///
/// The move itself: `do_migrate_pages` builds source→destination node pairs
/// and skips every pair where source == destination. With one node the only
/// legal destination is the node every page already occupies, so the walk
/// finds no pair to migrate and reports 0 pages left un-migrated. That is the
/// real Linux result on a one-node machine, not a shortcut.
/// # C: O(maxnode / 64 + N_tasks)
pub fn sys_migrate_pages(args: &SyscallArgs) -> i64 {
    let (pid, maxnode, old_nodes, new_nodes) = (args.a0 as u32, args.a1, args.a2, args.a3);
    let _old = match read_nodemask(old_nodes, maxnode) { Ok(n) => n, Err(rv) => return rv };
    let new = match read_nodemask(new_nodes, maxnode) { Ok(n) => n, Err(rv) => return rv };
    let Some(cur) = sched::live::current() else { return err(Errno::Esrch) };
    // `find_task_by_vpid(pid)` — pid 0 means the caller, which trivially
    // passes `ptrace_may_access` (same thread group).
    let target = if pid == 0 { None } else {
        match sched::live::registry::resolve_user_pid(pid) {
            Some(t) => Some(t), None => return err(Errno::Esrch),
        }
    };
    if let Some(t) = target.as_ref() {
        if crate::s101_ptrace_perm::may_access(&cur, t).is_err() { return err(Errno::Eperm); }
    }
    // `cpuset_mems_allowed(task)` — no cpuset controller narrows it, so it is
    // every node with memory.
    let task_nodes = nodes_with_memory();
    if !new.subset_of(task_nodes) && !cap_sys_nice() { return err(Errno::Eperm); }
    // `if (!nodes_and(*new, *new, task_nodes)) goto out_put;` with err still
    // seeded to -EINVAL: a destination set that names no usable node is
    // EINVAL, not a silent success.
    if new.and(task_nodes).is_empty() { return err(Errno::Einval); }
    // `get_task_mm(task)` — a kernel thread or an exiting task has none.
    let has_mm = match target.as_ref() {
        Some(t) => t.clone_mm().is_some(), None => cur.clone_mm().is_some(),
    };
    if !has_mm { return err(Errno::Einval); }
    0
}
