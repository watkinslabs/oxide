// `kernel.shm_rmid_forced`: the per-IPC-namespace force-reclaim flag, plus the
// orphan sweep its write side runs.
//
// The flag is a property of the IPC namespace, exactly like the shm registry
// itself — both are keyed by the canonical owner's `NamespaceId`, so a task
// that enters a new IPC namespace sees that namespace's flag and its own
// segments, and the namespace finalizer drops both together.
//
// Only namespaces with the flag SET are recorded; absence is the default 0.

use alloc::vec::Vec;
use namespace_identity::NamespaceId;
use sync::{Spinlock, TaskList as ShmLockClass};

use super::rules::shm_may_destroy;
use super::REG;

/// `proc_dointvec_minmax` window for the leaf (`extra1`/`extra2`).
pub const RMID_FORCED_BOUNDS: (i64, i64) = (0, 1);

static FORCED: Spinlock<Vec<NamespaceId>, ShmLockClass> = Spinlock::new(Vec::new());

/// The namespace's `shm_rmid_forced`. # C: O(N_forced_namespaces)
pub(super) fn is_forced(ns: NamespaceId) -> bool { FORCED.lock().iter().any(|n| *n == ns) }

/// Drop a finalized namespace's flag. # C: O(N_forced_namespaces)
pub(super) fn reap_namespace(ns: NamespaceId) { FORCED.lock().retain(|n| *n != ns); }

/// `kernel.shm_rmid_forced` read side, for the caller's IPC namespace.
/// # C: O(N_forced_namespaces)
pub fn shm_rmid_forced() -> i64 {
    match crate::ipc_namespace::current() {
        Ok(owner) => is_forced(owner.key()) as i64,
        Err(_) => 0,
    }
}

/// `kernel.shm_rmid_forced` write side (`proc_ipc_dointvec_minmax_orphans`):
/// store the value, then — when it is now set — sweep the namespace's already
/// orphaned segments, which is the whole reason the knob is useful after the
/// fact rather than only for segments created later.
/// # C: O(N_forced_namespaces + N_segments)
pub fn set_shm_rmid_forced(v: i64) {
    let Ok(owner) = crate::ipc_namespace::current() else { return };
    let ns = owner.key();
    {
        let mut g = FORCED.lock();
        let present = g.iter().any(|n| *n == ns);
        if v != 0 && !present { g.push(ns); } else if v == 0 && present { g.retain(|n| *n != ns); }
    }
    if v != 0 { destroy_orphaned(ns); }
}

/// `shm_destroy_orphaned`: destroy every segment of `ns` that has no
/// attachments left AND whose creator has already exited (`exit_shm` cleared
/// the creator back-reference). A segment whose creator is still alive is
/// left alone — that task may yet attach to it.
/// # C: O(N_segments)
pub(super) fn destroy_orphaned(ns: NamespaceId) {
    let forced = is_forced(ns);
    let doomed: Vec<_> = {
        let mut g = REG.segs.lock();
        let mut out = Vec::new();
        let mut i = 0;
        while i < g.len() {
            let s = &g[i];
            let orphan = s.ns == ns && s.creator.lock().is_none();
            let nattch = s.nattch.load(core::sync::atomic::Ordering::Acquire);
            if orphan && shm_may_destroy(nattch, forced, s.mode) { out.push(g.remove(i)); } else { i += 1; }
        }
        out
    };
    // The backing objects are released with the registry lock dropped, for the
    // same reason `release_detached` does it: a segment's last reference tears
    // down its shmem inode, which takes locks of its own.
    drop(doomed);
}
