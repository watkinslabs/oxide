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
        t.sigpending.fetch_or(crate::signum::Signum::Sigkill.bit(), Ordering::Release);
        crate::live::signal_wake_up(&t);
    }
}
