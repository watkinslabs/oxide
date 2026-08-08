//! `shrink_submounts` — the pass `umount(2)` owes an
//! automounted tree before it declares the target busy.
//!
//! An automounter (autofs, NFS crossmnt) parks its short-lived submounts on an
//! expire list. Those submounts are exactly what the automounter would have
//! reaped on its own next idle sweep, so upstream reaps them EAGERLY when
//! something tries to unmount the directory above them: a mount whose only
//! children are expirable submounts is NOT busy. Without this pass, unmounting
//! an autofs-managed parent reported `EBUSY` where Linux succeeds — and the
//! caller had no way to make progress short of `MNT_DETACH`, which is a
//! different operation with different visibility.
//!
//! The pass runs only for a non-lazy unmount: `MNT_DETACH` takes the subtree
//! down wholesale and never consults the busy test at all.
//!
//! Split from `expiry` because the selection rule is different: the sweep walks
//! ONE expire list's members, this walks the subtree of one mount and takes
//! whichever members it finds there, repeatedly, so a shrinkable mount that
//! only became childless because its own shrinkable children were reaped is
//! caught on the next pass.

use super::*;
use super::busy::{propagate_mount_busy, PASSIVE_REFCNT};

/// Linux `MNT_SHRINKABLE`: this mount was registered by an automounter as
/// disposable. The expire-list membership an automounter establishes at mount
/// time IS that registration, so the flag has no second, drift-prone home.
/// # C: O(N_lists × N_members)
fn is_shrinkable(m: &Arc<Mount>) -> bool { super::expiry::on_any_expire_list(m.mnt_id) }

/// Linux `select_submounts`: the shrinkable, non-busy mounts in `parent`'s
/// subtree, reachable through shrinkable mounts only.
///
/// A shrinkable mount that still carries children is DESCENDED INTO rather than
/// collected — it is busy by definition, and its own shrinkable children are
/// what this pass is looking for. A non-shrinkable mount ends the search down
/// that branch: nothing below an ordinary mount is the automounter's to reap.
/// # C: O(N_subtree × N_mirrors)
fn select_submounts(parent: &Arc<Mount>) -> Vec<Arc<Mount>> {
    let mut out: Vec<Arc<Mount>> = Vec::new();
    // Explicit frontier rather than recursion: mount depth is caller-controlled
    // and the kernel stack is guard-paged, not elastic.
    let mut frontier: Vec<Arc<Mount>> = alloc::vec![parent.clone()];
    while let Some(p) = frontier.pop() {
        let children: Vec<Arc<Mount>> = p.mnt_mounts.lock().iter().cloned().collect();
        for m in children {
            if !is_shrinkable(&m) { continue; }
            if m.has_child_mounts() { frontier.push(m); continue; }
            if !propagate_mount_busy(&m, PASSIVE_REFCNT) { out.push(m); }
        }
    }
    out
}

/// Linux `shrink_submounts(mnt)`: reap every expirable submount under `mnt`,
/// repeating until a pass finds none — each round frees the round above it, so
/// a whole automounted stack collapses. Returns the count reaped.
///
/// Each reap goes through the same detach path a real unmount uses, so the
/// mount-namespace watchers see it. # C: O(N_subtree²) worst case
pub fn shrink_submounts(parent: &Arc<Mount>) -> usize {
    let mut n = 0;
    loop {
        let selected = select_submounts(parent);
        if selected.is_empty() { return n; }
        for m in selected.iter() {
            super::detach::detach_with_propagation(m);
            n += 1;
        }
    }
}
