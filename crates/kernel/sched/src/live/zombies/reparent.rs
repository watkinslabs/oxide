// `forget_original_parent` / `reparent_leader` (Linux `kernel/exit.c`).
//
// Adoption order is NOT "always init": a live thread of the dying task's own
// group comes first (`find_alive_thread`), then the nearest
// `PR_SET_CHILD_SUBREAPER` ancestor, then the `child_reaper` of the dying
// task's OWN pid namespace. Handing a thread's children to init while its
// process is still running loses them for that process's `wait4`; handing a
// container's orphans to the host's PID 1 leaks them out of the namespace.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::exit::reaper::{find_new_reaper, Ancestor, NewReaper};
use crate::{registry, Task, TaskState};

/// How deep the `real_parent` walk in [`subreaper_chain`] may go before it
/// gives up — a cycle-proof bound, not a policy limit.
const MAX_ANCESTOR_DEPTH: usize = 64;

/// B14: repair queued zombies whose parent is gone.
/// # C: O(N_zombies x N_tasks)
pub fn reap_orphans() {
    let mut adopted: alloc::vec::Vec<(Arc<Task>, Arc<Task>)> = alloc::vec::Vec::new();
    {
        let q = super::ZOMBIES.lock();
        for t in q.iter() {
            let pt = t.parent_tid.load(Ordering::Acquire);
            if pt == 0 { continue; }
            if registry::lookup(pt).is_some() { continue; }
            let Some(reaper) = super::pidns::namespace_child_reaper(t) else { continue };
            adopted.push((Arc::clone(t), reaper));
        }
    }
    for (zombie, reaper) in adopted {
        attach_to(&zombie, &reaper);
        super::push_child_event(&zombie, &reaper);
        reaper.sigpending.fetch_or(super::super::sigpend::Signum::Sigchld.bit(), Ordering::Release);
        super::wake_wait4_parent(reaper.tid);
        super::wake_task_for_signal(&reaper);
    }
}

/// Point `child`'s parent links at `reaper`. # C: O(1)
fn attach_to(child: &Task, reaper: &Arc<Task>) {
    child.parent_tid.store(reaper.tid, Ordering::Release);
    // `child` may be running on another CPU right now; `set_parent_weak` takes
    // `parent_arc`'s own lock so this write cannot race a concurrent reader.
    child.set_parent_weak(Some(Arc::downgrade(reaper)));
}

/// Linux `find_alive_thread`: a member of `tgid` that is not itself exiting.
/// # C: O(N_threads)
fn find_alive_thread(tgid: u32, excluding: u32) -> Option<Arc<Task>> {
    registry::thread_entries(tgid)
        .into_iter()
        .filter(|(_, tid)| *tid != excluding)
        .filter_map(|(_, tid)| registry::lookup(tid))
        .find(|t| !matches!(t.state(), TaskState::Zombie))
}

/// Walk `real_parent` upward, collecting the candidates `find_new_reaper`
/// scans. Truncated at the first ancestor outside the dying task's pid
/// namespace, which the pure walk also refuses to cross.
///
/// `find_alive_thread` is the expensive step (a registry scan), so it runs
/// ONLY for ancestors that actually set `PR_SET_CHILD_SUBREAPER` — the pure
/// walk never reads `alive_thread` on any other ancestor. That keeps an
/// ordinary exit at O(depth) point lookups instead of O(depth × N_tasks).
/// # C: O(depth) + O(N_tasks) per subreaper ancestor
fn subreaper_chain(dying: &Task, ns_level: u32) -> alloc::vec::Vec<(Ancestor, Arc<Task>)> {
    let mut out = alloc::vec::Vec::new();
    let mut next = dying.parent();
    for _ in 0..MAX_ANCESTOR_DEPTH {
        let Some(p) = next else { break };
        let is_child_subreaper = p.child_subreaper.load(Ordering::Acquire);
        let alive = if is_child_subreaper {
            find_alive_thread(p.tgid.load(Ordering::Acquire), u32::MAX)
        } else {
            None
        };
        let ancestor = Ancestor {
            tid: p.tid,
            ns_level: pid_ns_level(&p),
            is_child_subreaper,
            alive_thread: alive.as_ref().map(|t| t.tid),
            is_init_task: p.vtgid.load(Ordering::Acquire) == super::pidns::INIT_VPID
                && super::pidns::in_initial_pid_namespace(&p),
        };
        next = p.parent();
        let crossed = ancestor.ns_level != ns_level;
        out.push((ancestor, alive.unwrap_or(p)));
        if crossed { break; }
    }
    out
}

/// Stand-in for Linux `task_pid(p)->level`: tasks of the initial pid namespace
/// are level 0, everything else level 1. Nested namespaces beyond one level
/// collapse to the same level, which only makes the walk MORE conservative
/// (it stops at the first namespace change either way).
/// # C: O(1)
fn pid_ns_level(task: &Task) -> u32 {
    if super::pidns::in_initial_pid_namespace(task) { 0 } else { 1 }
}

/// Linux `forget_original_parent`: hand every child of the exiting task to the
/// reaper chosen by `find_new_reaper`, delivering `PR_SET_PDEATHSIG` on the
/// way and re-notifying the new parent about children that are already
/// zombies (`reparent_leader`).
/// # C: O(N_tasks)
pub fn reparent_children(dying_tid: u32) {
    let Some(dying) = registry::lookup(dying_tid) else { return };
    let dying_tgid = dying.tgid.load(Ordering::Acquire);
    let ns_level = pid_ns_level(&dying);
    let alive_sibling = find_alive_thread(dying_tgid, dying_tid);
    // Linux gates the ancestor walk on `signal->has_child_subreaper`, a
    // clone-time-propagated hint. A live sibling wins outright, so the walk is
    // skipped entirely in the common threaded case; otherwise walking reaches
    // the same answer the hint would, bounded by process depth.
    let chain = if alive_sibling.is_some() {
        alloc::vec::Vec::new()
    } else {
        subreaper_chain(&dying, ns_level)
    };
    let ancestors: alloc::vec::Vec<Ancestor> = chain.iter().map(|(a, _)| *a).collect();
    let choice = find_new_reaper(
        alive_sibling.as_ref().map(|t| t.tid), true, ns_level, &ancestors);
    let reaper = match choice {
        NewReaper::AliveSibling(_) => alive_sibling,
        NewReaper::Subreaper(tid)  => chain.iter().find(|(_, t)| t.tid == tid).map(|(_, t)| Arc::clone(t)),
        NewReaper::NsInit          => super::pidns::namespace_child_reaper(&dying),
    };
    let Some(reaper) = reaper else { return };
    // A threaded reparent (the reaper is another thread of the SAME group)
    // notifies nobody: nothing observable changed for the process.
    let threaded = reaper.tgid.load(Ordering::Acquire) == dying_tgid;
    let mut reparented_zombie = false;
    for tid in registry::live_tids() {
        let Some(t) = registry::lookup(tid) else { continue };
        if t.parent_tid.load(Ordering::Acquire) != dying_tid { continue; }
        let pds = t.pdeathsig.load(Ordering::Acquire);
        if let Some(bit) = crate::bit_for(pds as u32) {
            t.sigpending.fetch_or(bit, Ordering::Release);
            crate::live::signal_wake_up(&t);
        }
        attach_to(&t, &reaper);
        if threaded { continue; }
        // Linux `reparent_leader`: "We don't want people slaying init."
        t.exit_signal.store(super::super::sigpend::Signum::Sigchld.as_u8(), Ordering::Release);
        if matches!(t.state(), TaskState::Zombie) {
            super::push_child_event(&t, &reaper);
            reparented_zombie = true;
        }
        // The child's process group may have just lost its last outside
        // connection (POSIX 3.2.2.2).
        super::orphan::kill_orphaned_pgrp(&t, Some(&dying));
    }
    if reparented_zombie {
        reaper.sigpending.fetch_or(super::super::sigpend::Signum::Sigchld.bit(), Ordering::Release);
        super::wake_wait4_parent(reaper.tid);
        super::wake_task_for_signal(&reaper);
    }
}
