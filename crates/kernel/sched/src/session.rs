// POSIX session / process-group work fns (`docs/53§3`): the real bodies behind
// slots 109 setpgid, 110 getppid, 111 getpgrp, 112 setsid, 121 getpgid,
// 124 getsid. Modelled line-for-line on Linux `kernel/sys.c`
// (`SYSCALL_DEFINE2(setpgid)`, `do_getpgid`, `SYSCALL_DEFINE1(getsid)`,
// `ksys_setsid`, `SYSCALL_DEFINE0(getppid)`), including the exact order errors
// are returned in — job-control code depends on distinguishing EPERM from
// EACCES from ESRCH on the same call.
//
// Every fn takes the caller as a typed `&Task` and returns `Result<_, Errno>`,
// so the whole error ladder is drivable from hosted `cargo test` without a
// syscall frame.
//
// pgid/sid are read through `Task::pgid()`/`Task::sid()`, which forward to the
// task's `ThreadGroup` — Linux keeps them in `task->signal`, shared by every
// thread, and so do we.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use namespace_identity::{NamespaceKind, NamespaceRef};
use syscall::errno::Errno;

use crate::registry;
use crate::Task;

/// Pid namespace a user-supplied pid argument is interpreted in. Falls back to
/// the initial namespace for tasks with no namespace set (kthreads, hosted
/// fixtures), matching `registry::resolve_user_pid`. # C: O(1)
fn pid_ns(cur: &Task) -> NamespaceRef {
    cur.namespace_owner(NamespaceKind::Pid)
        .unwrap_or_else(|| namespace_identity::initial(NamespaceKind::Pid))
}

/// Linux `task_tgid_vnr(p)` — the PROCESS id userspace sees for `t`. Every
/// thread of a group carries the leader's `vtgid`, so this is correct from any
/// member without resolving the leader. Falls back to the internal tgid for
/// tasks with no vpid stamped (kthreads, hosted fixtures), matching
/// `registry::display_vpid`.
/// # C: O(1)
pub fn process_vpid(t: &Task) -> u32 {
    let v = t.vtgid.load(Ordering::Acquire);
    if v != 0 { v } else { t.tgid.load(Ordering::Acquire) }
}

/// Whether `a` and `b` are threads of one process (Linux `same_thread_group`).
/// # C: O(1)
fn same_thread_group(a: &Task, b: &Task) -> bool {
    Arc::ptr_eq(&a.thread_group, &b.thread_group)
}

/// Whether `p` IS the caller's thread-group leader (Linux `p == group_leader`).
/// A leader's internal tid equals its tgid, so this is an identity test.
/// # C: O(1)
fn is_callers_group_leader(p: &Task, cur: &Task) -> bool {
    p.tid == cur.tgid.load(Ordering::Acquire)
}

/// Linux `SYSCALL_DEFINE0(getppid)`: `task_tgid_vnr(current->real_parent)`.
/// A parent outside the caller's pid namespace — or already gone, as for pid 1
/// whose parent is the kernel — reports 0, exactly as `task_tgid_vnr` does when
/// the pid has no number in that namespace.
/// # C: O(log N_tasks)
pub fn getppid(cur: &Task) -> u32 {
    let ptid = cur.parent_tid.load(Ordering::Acquire);
    let Some(parent) = registry::lookup(ptid) else { return 0 };
    let ns = pid_ns(cur);
    let leader_tid = parent.tgid.load(Ordering::Acquire);
    let leader = registry::lookup(leader_tid).unwrap_or(parent);
    leader.pid.visible_tid(&ns).unwrap_or_else(|| process_vpid(&leader))
}

/// Linux `do_getpgid`: `pid == 0` means the caller; any other pid must resolve
/// to a live task in the caller's pid namespace or the call is ESRCH.
/// # C: O(log N_tasks) init-ns; O(N_tasks) otherwise
pub fn getpgid(cur: &Task, pid: i32) -> Result<u32, Errno> {
    if pid == 0 { return Ok(cur.pgid()); }
    Ok(lookup_user_pid(cur, pid).ok_or(Errno::Esrch)?.pgid())
}

/// Linux `SYSCALL_DEFINE1(getsid)`. Same shape as `getpgid`, on the session id.
/// # C: O(log N_tasks) init-ns; O(N_tasks) otherwise
pub fn getsid(cur: &Task, pid: i32) -> Result<u32, Errno> {
    if pid == 0 { return Ok(cur.sid()); }
    Ok(lookup_user_pid(cur, pid).ok_or(Errno::Esrch)?.sid())
}

/// Resolve a userspace-supplied positive pid inside the caller's pid namespace.
/// A negative pid can never name a task, so it resolves to `None` (ESRCH at the
/// call site) rather than wrapping into a huge u32.
/// # C: O(log N_tasks) init-ns; O(N_tasks) otherwise
fn lookup_user_pid(cur: &Task, pid: i32) -> Option<Arc<Task>> {
    if pid < 0 { return None; }
    registry::lookup_in_namespace(&pid_ns(cur), pid as u32)
}

/// Linux `SYSCALL_DEFINE2(setpgid, pid, pgid)`, whole ladder in order:
///
/// | check | errno |
/// |---|---|
/// | `pgid < 0` (after the `pid`/`pgid` 0-aliases) | EINVAL |
/// | target pid names no live task | ESRCH |
/// | target is not a thread-group leader | EINVAL |
/// | target is our child, in a different session | EPERM |
/// | target is our child that already `execve`d | EACCES |
/// | target is neither us nor our child | ESRCH |
/// | target is a session leader | EPERM |
/// | destination pgrp has no member in our session | EPERM |
///
/// `pid == 0` means the caller's process; `pgid == 0` means "the process group
/// whose id equals `pid`", i.e. make the target its own group leader.
/// # C: O(N_tasks) worst case (destination-pgrp membership scan)
pub fn setpgid(cur: &Task, pid: i32, pgid: i32) -> Result<(), Errno> {
    let pid = if pid == 0 { process_vpid(cur) as i32 } else { pid };
    let pgid = if pgid == 0 { pid } else { pgid };
    if pgid < 0 { return Err(Errno::Einval); }

    let p = lookup_user_pid(cur, pid).ok_or(Errno::Esrch)?;
    if !p.pid.is_group_leader() { return Err(Errno::Einval); }

    if is_our_child(cur, &p) {
        // A parent may only move a child that is still in the same session and
        // has not yet exec'd — POSIX's fork/setpgid/exec job-control window.
        if p.sid() != cur.sid() { return Err(Errno::Eperm); }
        if !p.forknoexec.load(Ordering::Acquire) { return Err(Errno::Eacces); }
    } else if !is_callers_group_leader(&p, cur) {
        // Neither our child nor ourselves: Linux hides the task's existence.
        return Err(Errno::Esrch);
    }

    if p.thread_group.is_session_leader() { return Err(Errno::Eperm); }

    if pgid != pid {
        // Joining an EXISTING group: it must exist and live in our session.
        // (`pgid == pid` creates the group led by the target, so no member
        // exists yet and Linux skips this check entirely.)
        let sid = cur.sid();
        let joinable = registry::tasks_in_pgrp(pgid as u32)
            .into_iter()
            .any(|g| g.sid() == sid);
        if !joinable { return Err(Errno::Eperm); }
    }

    p.set_pgid(pgid as u32);
    Ok(())
}

/// Linux `ksys_setsid`. Creates a new session AND a new process group, both
/// numbered with the caller's process id, and drops the controlling terminal.
///
/// EPERM when the calling process is already a session leader, or when a
/// process group numbered with the caller's pid already exists — the latter is
/// the "caller is already a process group leader" case, since a process group
/// is only ever numbered after its leader.
/// # C: O(N_tasks) (pgrp-existence scan)
/// # Ctx: `cur` must be the running task on this CPU (`ctty` single-mutator).
pub fn setsid(cur: &Task) -> Result<u32, Errno> {
    let session = process_vpid(cur);
    if cur.thread_group.is_session_leader() { return Err(Errno::Eperm); }
    if !registry::tasks_in_pgrp(session).is_empty() { return Err(Errno::Eperm); }
    if !cur.thread_group.claim_session_leader() { return Err(Errno::Eperm); }

    cur.set_sid(session);
    cur.set_pgid(session);
    // Linux `proc_clear_tty(group_leader)`: a new session starts with no
    // controlling terminal.
    // SAFETY: `ctty` is written only by the running task on its own CPU per the
    // `13§5` single-mutator invariant; this is that task's own syscall path.
    unsafe { *cur.ctty.get() = None; }
    Ok(session)
}

/// Linux `same_thread_group(p->real_parent, current->group_leader)`: is `p` a
/// child of the calling PROCESS (not merely of the calling thread)?
/// # C: O(log N_tasks)
fn is_our_child(cur: &Task, p: &Task) -> bool {
    let ptid = p.parent_tid.load(Ordering::Acquire);
    match registry::lookup(ptid) {
        Some(parent) => same_thread_group(&parent, cur),
        None => false,
    }
}
