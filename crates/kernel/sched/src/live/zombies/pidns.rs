// PID-namespace facts the exit path needs, and `zap_pid_ns_processes`.
//
// The reaper of a task's children is the `child_reaper` of the task's OWN pid
// namespace, not global PID 1 (Linux `find_child_reaper`:
// `task_active_pid_ns(father)->child_reaper`). Resolving it by scanning for a
// task whose visible pid is 1 is ambiguous the moment a container exists —
// every namespace has one — so every lookup here is namespace-qualified.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use namespace_identity::NamespaceKind;

use crate::{registry, Task};

/// The visible pid of a pid namespace's init, in every namespace.
pub const INIT_VPID: u32 = 1;

/// `task_active_pid_ns(task)` as a comparable id. `None` before the namespace
/// set is published (early boot).
/// # C: O(1)
pub fn pid_namespace_id(task: &Task) -> Option<u64> {
    task.namespace_id(NamespaceKind::Pid)
}

/// `task_active_pid_ns(task)` and each of its ancestors, nearest first — the
/// walk Linux spells `for (ns = task_active_pid_ns(current); ns; ns = ns->parent)`.
///
/// Used by anything that must consult a per-pid-namespace setting AND every
/// enclosing namespace's copy of it: `acct_process()` writes one accounting
/// record per ancestor namespace that opted in, so a process exiting inside a
/// container is accounted by the container and by the host.
///
/// Always ends at the initial namespace (id 0), including before the namespace
/// set is published at early boot — a task with no namespace identity yet is
/// in the initial one by definition.
/// # C: O(depth)
pub fn pid_namespace_chain(task: &Task) -> alloc::vec::Vec<u64> {
    let mut out = alloc::vec::Vec::new();
    let mut cur = task.namespace_owner(NamespaceKind::Pid).map(|ns| ns.pin());
    while let Some(pin) = cur {
        let id = pin.ns_id().as_u64();
        if !out.contains(&id) { out.push(id); }
        cur = pin.parent();
    }
    if !out.contains(&0) { out.push(0); }
    out
}

/// Whether `task` is the init of its own pid namespace — the task signals it
/// did not ask for cannot kill. Such a task must not gain siblings: nothing
/// would reap them.
/// # C: O(1)
pub fn is_namespace_init(task: &Task) -> bool {
    task.vtgid.load(core::sync::atomic::Ordering::Acquire) == 1
}

/// Whether `task` lives in the INITIAL pid namespace — the qualifier that
/// turns "vpid 1" into Linux's `is_global_init`. # C: O(1)
pub fn in_initial_pid_namespace(task: &Task) -> bool {
    task.namespace_owner(NamespaceKind::Pid).is_none_or(|ns| ns.is_initial())
}

/// Linux `task_active_pid_ns(father)->child_reaper`: the init of `task`'s own
/// pid namespace. Falls back to the initial namespace's init when the
/// namespace has no live init left, mirroring the fact that a namespace
/// without a reaper is being torn down anyway.
/// # C: O(N_tasks)
pub fn namespace_child_reaper(task: &Task) -> Option<Arc<Task>> {
    let ns = pid_namespace_id(task);
    let mut fallback = None;
    for tid in registry::live_tids() {
        let Some(t) = registry::lookup(tid) else { continue };
        if t.vtgid.load(Ordering::Acquire) != INIT_VPID { continue; }
        if t.tid != t.tgid.load(Ordering::Acquire) { continue; }
        if pid_namespace_id(&t) == ns { return Some(t); }
        if fallback.is_none() && in_initial_pid_namespace(&t) { fallback = Some(t); }
    }
    fallback
}

/// Linux `cad_pid`'s default target — `cad_pid = task_pid(&init_task)`
/// (`kernel/reboot.c`), i.e. the init of the INITIAL pid namespace. Used by
/// `ctrl_alt_del()` to deliver SIGINT when `C_A_D` is clear.
///
/// The visible pid is `vtgid` when set and the real `tgid` otherwise — an
/// initial-namespace task leaves `vtgid` at 0 (`Task::vtgid`: "0 means use the
/// real tgid"), so matching on `vtgid == 1` alone never finds the real init.
/// # C: O(N_tasks)
pub fn initial_init_task() -> Option<Arc<Task>> {
    for tid in registry::live_tids() {
        let Some(t) = registry::lookup(tid) else { continue };
        let tgid = t.tgid.load(Ordering::Acquire);
        if t.tid != tgid { continue; }
        let vtgid = t.vtgid.load(Ordering::Acquire);
        let visible = if vtgid != 0 { vtgid } else { tgid };
        if visible != INIT_VPID { continue; }
        if in_initial_pid_namespace(&t) { return Some(t); }
    }
    None
}

/// Linux `zap_pid_ns_processes`: a pid namespace that loses its init loses
/// every member. SIGKILL each remaining task of `task`'s namespace so they run
/// their own fatal-signal exit; the machine is unaffected.
/// # C: O(N_tasks)
pub fn zap_pid_namespace(task: &Task) {
    let Some(ns) = pid_namespace_id(task) else { return };
    let self_tid = task.tid;
    for tid in registry::live_tids() {
        if tid == self_tid { continue; }
        let Some(t) = registry::lookup(tid) else { continue };
        if pid_namespace_id(&t) != Some(ns) { continue; }
        crate::live::send_sig_priv_group(&t, crate::signum::Signum::Sigkill as u32);
    }
}
