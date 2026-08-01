// vpid(vtgid)-keyed resolution: namespace-aware pid lookup, the userspace
// pid→Task entrypoint, and the vpid/vtid/parent-vpid display helpers procfs
// renders. `lookup_by_vpid` is the hot path for `/proc/<pid>/*` reads —
// accelerated by `core::Registry::vpid_hint`, self-validated on every hit.

use alloc::sync::Arc;
use alloc::vec::Vec;
use namespace_identity::{NamespaceKind, NamespaceRef};

use super::core::{RegIrq, REG};
use super::tid::lookup;
use crate::Task;

/// Resolve `(ns, vpid)` → live `Arc<Task>`. F109: pid-NS-aware
/// lookup for kill/wait4/tgkill from a task in a non-init pid_ns —
/// caller's vpid arg is interpreted within their NS instead of as a
/// real tid. Init-NS callers (`ns == 0`) match by real tid (the
/// init-NS shortcut).
/// # C: O(log N_tasks) init-NS shortcut; O(N_tasks) otherwise
pub fn lookup_in_namespace(ns: &NamespaceRef, vpid: u32) -> Option<Arc<Task>> {
    use core::sync::atomic::Ordering;
    if ns.is_initial() {
        // Init NS: kernel-side callers pass an internal tid; userspace passes
        // the pid it actually sees — a vpid/vtid (getpid/gettid/fork return
        // those, NOT the opaque internal tid; NEXT_TID base is far above the
        // small vpid range so the two never collide). Match internal tid
        // FIRST (preserves every existing kernel caller verbatim), then fall
        // back to vtid/vtgid so userspace signal targeting resolves the Linux
        // way (by the visible pid): e.g. musl raise()→tkill(gettid()) and
        // kill(getpid()) must hit self. Previously only `lookup(vpid)`
        // (internal tid) ran, so raise/abort/pthread_kill silently ESRCH'd and
        // the signal was never posted (verified: the handler never ran).
        if let Some(t) = lookup(vpid) {
            return if t.reaped.load(Ordering::Acquire) { None } else { Some(t) };
        }
    }
    super::snapshot::snapshot_tasks_for_pid_lookup().into_iter().find(|t| {
        !t.reaped.load(Ordering::Acquire)
            && t.pid.visible_tid(ns) == Some(vpid)
    })
}

/// Linux `task_pid_vnr(p)`: the thread number `t` carries inside `ns`, or
/// `None` when `ns` does not number `t` at all — Linux's `0`, which every
/// PRIO_USER / IOPRIO_WHO_USER walk uses to skip tasks the caller cannot name.
///
/// The initial namespace numbers every task, so it falls back to the vtid (or
/// the internal tid for a task that never got one stamped) exactly as
/// [`lookup_in_namespace`]'s init-NS shortcut does; without that fallback a
/// system that never published pid mappings would report every task invisible.
/// # C: O(depth)
pub fn vnr_in(t: &Task, ns: &NamespaceRef) -> Option<u32> {
    use core::sync::atomic::Ordering;
    if let Some(nr) = t.pid.visible_tid(ns) { return Some(nr); }
    if !ns.is_initial() { return None; }
    let vtid = t.vtid.load(Ordering::Acquire);
    Some(if vtid != 0 { vtid } else { t.tid })
}

/// The caller's pid namespace, snapshotted once so a target-set walk does not
/// re-resolve it per task. `None` outside a live task (kthread bring-up,
/// hosted fixtures), which callers treat as the initial namespace.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn caller_pid_ns() -> Option<NamespaceRef> {
    crate::live::current()?.namespace_owner(NamespaceKind::Pid)
}

/// The pid namespace every number rendered on this call must be expressed in:
/// the READER's, which is what decides whether a task is nameable at all and
/// which of its numbers is the right one. Outside a live task (boot, kernel
/// log, hosted fixtures) that is the initial namespace, which numbers
/// everything. # C: O(1)
pub fn reader_pid_ns() -> NamespaceRef {
    #[cfg(target_os = "oxide-kernel")]
    { caller_pid_ns().unwrap_or_else(|| namespace_identity::initial(NamespaceKind::Pid)) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { namespace_identity::initial(NamespaceKind::Pid) }
}

/// Linux `task_tgid_nr_ns(p, ns)`: the PROCESS number `t` belongs to as `ns`
/// sees it, or `None` when `ns` does not number that process. A thread reports
/// its group leader's number, which is the pid every process-scoped interface
/// (`/proc/<pid>`, credentials, `getpid`) reports for it.
/// # C: O(log N_tasks + depth)
pub fn tgid_nr_in(t: &Task, ns: &NamespaceRef) -> Option<u32> {
    use core::sync::atomic::Ordering;
    let tgid = t.tgid.load(Ordering::Acquire);
    match if tgid == t.tid { None } else { lookup(tgid) } {
        Some(leader) => leader_tgid_nr_in(&leader, ns),
        None => leader_tgid_nr_in(t, ns),
    }
}

/// `tgid_nr_in` for a task already known to be its group's leader, which every
/// zombie and every wait candidate is. Touches no registry entry, so it is the
/// form callers holding the registry lock must use. # C: O(depth)
pub fn leader_tgid_nr_in(t: &Task, ns: &NamespaceRef) -> Option<u32> {
    use core::sync::atomic::Ordering;
    if let Some(nr) = t.pid.visible_tid(ns) { return Some(nr); }
    if !ns.is_initial() { return None; }
    let vtgid = t.vtgid.load(Ordering::Acquire);
    Some(if vtgid != 0 { vtgid } else { t.tgid.load(Ordering::Acquire) })
}

/// Resolve a USERSPACE-supplied pid/tid (the value getpid/gettid/fork return)
/// to a Task, interpreted in the CALLER's pid namespace. THIS is the correct
/// primitive for any syscall whose pid arg comes from userspace (kill,
/// sched_*, getpgid/setpgid, …) — NOT `lookup`, which keys the opaque
/// internal tid and so silently fails on a userspace vpid (the
/// pid_identity minefield). `pid == 0` is the caller's responsibility (means
/// "self"/"caller's pgrp" depending on the syscall).
/// # C: O(log N_tasks) init-NS shortcut; O(N_tasks) otherwise
pub fn resolve_user_pid(pid: u32) -> Option<Arc<Task>> {
    #[cfg(target_os = "oxide-kernel")]
    let ns = {
        crate::live::current()?.namespace_owner(NamespaceKind::Pid)?
    };
    #[cfg(not(target_os = "oxide-kernel"))]
    let ns = namespace_identity::initial(NamespaceKind::Pid);
    lookup_in_namespace(&ns, pid)
}

/// Resolve a userspace PID (vtgid) to a Task. Different from
/// `lookup` which keys on the kernel-internal TID. Used by procfs's
/// `/proc/<PID>` lookup so `cat /proc/1/status` sees init.
///
/// A process vpid is now shared by EVERY thread of the group (CLONE_THREAD
/// copies the leader's vtgid), so a bare `vtgid == vpid` match is ambiguous.
/// Resolve to the thread-group LEADER — the task whose `vtid == vtgid` — so
/// `/proc/<pid>/…` and `cgroup.procs` writes both land on the single task
/// that owns the process's cgroup membership (its internal tid == its tgid,
/// the key the cgroup tree stores under). Fall back to any group member if
/// the leader has already exited (a non-leader thread keeps the group alive).
///
/// Fast path: `Registry::vpid_hint` — re-validated against the canonical
/// `vtgid`/`vtid`/`reaped` fields before being trusted, so a stale hint
/// (thread exit, `unshare(CLONE_NEWPID)` rebind) degrades to the O(N_tasks)
/// scan below rather than ever returning a wrong task.
/// # C: O(log N_tasks) hint hit; O(N_tasks) fallback scan
pub fn lookup_by_vpid(vpid: u32) -> Option<Arc<Task>> {
    use core::sync::atomic::Ordering;
    let ns = reader_pid_ns();
    let mut g = REG.lock_irqsave::<RegIrq>();
    if let Some(w) = g.vpid_hint.get(&vpid) {
        match w.upgrade() {
            Some(t) if !t.reaped.load(Ordering::Acquire)
                && tgid_nr_in(&t, &ns) == Some(vpid)
                && t.vtid.load(Ordering::Acquire) == t.vtgid.load(Ordering::Acquire) =>
            {
                return Some(t);
            }
            None => { g.vpid_hint.remove(&vpid); } // deterministic prune: confirmed-dead
            _ => {} // stale, non-leader, or foreign-namespace hint: authoritative scan
        }
    }
    let mut fallback: Option<Arc<Task>> = None;
    let mut leader: Option<alloc::sync::Weak<Task>> = None;
    for (_, w) in g.by_tid.iter() {
        let Some(t) = w.upgrade() else { continue };
        if t.reaped.load(Ordering::Acquire) || tgid_nr_in(&t, &ns) != Some(vpid) {
            continue;
        }
        if t.vtid.load(Ordering::Acquire) == t.vtgid.load(Ordering::Acquire) {
            leader = Some(alloc::sync::Weak::clone(w));
            fallback = Some(t);
            break;
        }
        fallback.get_or_insert(t);
    }
    if let Some(w) = leader {
        g.vpid_hint.insert(vpid, w); // self-heal for the next lookup
    }
    fallback
}

/// Snapshot live process vtgids (Linux "PIDs") for procfs readdir.
/// Tasks without a vtgid (kernel threads pre-fork, smokes) are
/// skipped — they don't have a `/proc/N` directory in Linux either.
/// Sorted ascending for stable ordering.
/// # C: O(N_tasks log N_tasks)
pub fn live_vpids() -> Vec<u32> {
    use core::sync::atomic::Ordering;
    let ns = reader_pid_ns();
    let mut g = REG.lock_irqsave::<RegIrq>();
    super::core::prune_dead_locked(&mut g);
    let mut out: Vec<u32> = g
        .by_tid
        .iter()
        .filter_map(|(_, w)| w.upgrade())
        // Skip reaped tasks (Linux release_task): a pidfd-pinned reaped child is
        // still strong-ref alive but must not appear in /proc (else ps/htop show
        // it as a lingering zombie).
        .filter(|t| !t.reaped.load(Ordering::Acquire))
        // A reader only sees the processes its OWN namespace numbers, by the
        // number that namespace gives them: a task in a sibling or descendant
        // namespace has no name here and is not listed.
        .filter_map(|t| tgid_nr_in(&t, &ns))
        .filter(|&v| v != 0)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Namespace PID to display for the task with internal `tid`: its vtgid,
/// falling back to the internal tid for kernel threads / smokes that never
/// got a vpid stamped. procfs stat/status must show this (Linux "PID"),
/// not the opaque internal tid — PID1 is vtgid=1 but tid=0xC0DE….
/// # C: O(log N_tasks) via `lookup`.
pub fn display_vpid(tid: u32) -> u64 {
    use core::sync::atomic::Ordering;
    let ns = reader_pid_ns();
    if let Some(t) = lookup(tid) {
        if !t.reaped.load(Ordering::Acquire) {
            if let Some(v) = tgid_nr_in(&t, &ns) { if v != 0 { return v as u64; } }
            return 0;
        }
    }
    let g = REG.lock_irqsave::<RegIrq>();
    g.by_tid.values().filter_map(|weak| weak.upgrade()).find_map(|task| {
        (!task.reaped.load(Ordering::Acquire)
            && task.tgid.load(Ordering::Acquire) == tid)
            .then(|| tgid_nr_in(&task, &ns).unwrap_or(0) as u64)
            .filter(|vpid| *vpid != 0)
    }).unwrap_or(tid as u64)
}

/// Namespace thread id to display for the task with internal `tid`:
/// its `vtid`, falling back to the internal tid for init-NS tasks.
/// `/proc/<pid>/task/<tid>` must expose thread ids, not process ids.
/// # C: O(log N_tasks) via `lookup`.
pub fn display_vtid(tid: u32) -> u64 {
    let ns = reader_pid_ns();
    match lookup(tid) {
        Some(t) => vnr_in(&t, &ns).unwrap_or(0) as u64,
        None => tid as u64,
    }
}

/// Parent's namespace PID for the task with internal `tid`: resolve its
/// internal parent_tid to that parent's vtgid. PID1's parent is the kernel
/// → 0 (Linux shows PPid 0 for init).
/// # C: O(log N_tasks) — two registry lookups.
pub fn parent_vpid(tid: u32) -> u64 {
    use core::sync::atomic::Ordering;
    let ns = reader_pid_ns();
    let ptid = match lookup(tid) {
        Some(t) => t.parent_tid.load(Ordering::Acquire),
        None => return 0,
    };
    // A parent OUTSIDE the reader's namespace has no name there — Linux
    // reports PPid 0, which is what a namespace's init sees for its creator.
    lookup(ptid)
        .and_then(|p| tgid_nr_in(&p, &ns))
        .filter(|&v| v != 0)
        .unwrap_or(0) as u64
}

/// Numbers `t`'s THREAD identity carries from `reader`'s level inward to its
/// own, the `/proc/<pid>/status` `NSpid` row. Empty when `reader` does not
/// number `t`; a single-entry chain for a task the initial namespace numbers
/// without a published mapping. # C: O(depth)
pub fn nr_chain_in(t: &Task, reader: &NamespaceRef) -> Vec<u32> {
    let chain = t.pid.nr_chain_from(reader);
    if !chain.is_empty() { return chain; }
    match vnr_in(t, reader) { Some(nr) => alloc::vec![nr], None => Vec::new() }
}

/// Numbers the process, process group or session named `nr` in `owner` carries
/// from `reader`'s level inward — Linux's `task_tgid_nr_ns` /
/// `task_pgrp_nr_ns` / `task_session_nr_ns` rows. Empty when the number names
/// no live task, which is how a group whose leader has exited reports.
/// # C: O(N_tasks + depth)
pub fn group_chain(owner: &NamespaceRef, nr: u32, reader: &NamespaceRef) -> Vec<u32> {
    match lookup_in_namespace(owner, nr) {
        Some(t) => nr_chain_in(&t, reader),
        None => Vec::new(),
    }
}

/// The PROCESS number `t` carries as `viewer`'s pid namespace numbers it — the
/// value every `si_pid` must hold, because a signal's pid field is read by the
/// RECEIVER, in the receiver's namespace. 0 when the viewer's namespace does
/// not number `t` at all. # C: O(log N_tasks + depth)
pub fn tgid_nr_seen_by(t: &Task, viewer: &Task) -> u32 {
    let ns = viewer.namespace_owner(NamespaceKind::Pid)
        .unwrap_or_else(|| namespace_identity::initial(NamespaceKind::Pid));
    tgid_nr_in(t, &ns).unwrap_or(0)
}
