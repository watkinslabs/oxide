// Target-task resolution and the ptrace access gate, Linux
// `find_get_task_by_vpid` + `mm_access(task, PTRACE_MODE_ATTACH_REALCREDS)`.

use alloc::sync::Arc;
use syscall::errno::Errno;
use vmm::AddressSpace;

/// Resolve the target's `AddressSpace` and return the owning `Arc`, having
/// first applied Linux's access gate.
///
/// `mm_access` order, which is what a caller observes:
///   1. `find_get_task_by_vpid(pid)` — ESRCH. `pid <= 0` never names a task
///      (`find_vpid` starts its idr at 1), so it is ESRCH too.
///   2. `get_task_mm(task)` — a task with no mm (kernel thread, exited) is
///      ESRCH, and this precedes the permission check: a caller learns
///      "gone" before it learns "not permitted".
///   3. `may_access_mm`: an mm the caller ALREADY owns (self, or any
///      CLONE_VM peer) needs no check at all; otherwise
///      `ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS)`.
///      `process_vm_rw_core` rewrites that EACCES to EPERM.
///
/// The returned `Arc` also pins the address space: callers MUST hold it for
/// the whole `read_foreign_user`/`write_foreign_user` walk, since a bare
/// `root_pa` would let a concurrent exit/execve free the page tables (and
/// the frames) mid-copy.
/// # C: O(N_tasks) for the pid lookup; O(1) thereafter
pub(crate) fn target_mm(pid: i32) -> Result<Arc<AddressSpace>, i64> {
    let esrch = -(Errno::Esrch.as_i32() as i64);
    if pid <= 0 { return Err(esrch); }
    let cur = match sched::live::current() { Some(c) => c, None => return Err(esrch) };
    let task = match sched::live::registry::resolve_user_pid(pid as u32) {
        Some(t) => t, None => return Err(esrch),
    };
    // clone_mm pins against a concurrent exit/execve mm replacement on
    // another CPU; None is Linux's `!mm` ESRCH arm.
    let mm = match task.clone_mm() { Some(m) => m, None => return Err(esrch) };
    if !owns_mm(cur, &mm) && crate::s101_ptrace_perm::may_attach_access(cur, &task).is_err() {
        return Err(-(Errno::Eperm.as_i32() as i64));
    }
    Ok(mm)
}

/// Linux `may_access_mm`'s `mm == current->mm` shortcut. # C: O(1)
fn owns_mm(cur: &sched::Task, mm: &Arc<AddressSpace>) -> bool {
    // SAFETY: mm slot single-mutator per `13§5` — `owns_mm` runs on the running task's own syscall path, the sole reader of `cur.mm`.
    match unsafe { cur.mm_ref() } { Some(m) => Arc::ptr_eq(m, mm), None => false }
}
