//! Umount / detach machinery (`docs/16§6`): the tear-down entry points —
//! `umount(2)` (`unregister`), `d_invalidate` cover-dentry detach across all
//! namespaces (`detach_mounts_on`), and the subtree + propagate_umount path
//! (`unregister_top`). Split out of `mount.rs` to hold the line cap; all parent
//! state reached via `super::`. PURE MOVE — no behavior change, public surface
//! stays `vfs::mount::*`.

use super::*;
use super::propagation::propagation_targets;

/// `umount`: remove the mount rooted exactly at mountpoint dentry `d`.
/// Returns the count removed. # C: O(log N)
pub fn unregister(d: &Arc<Dentry>) -> usize {
    let ns = current_ns();
    let Some(target) = mount_exact_at(ns, d) else { return 0; };
    let id = target.mnt_id;
    let mp = target.mountpoint();
    let parent = target.parent_id.load(Ordering::Acquire);
    let sb = target.sb.clone();
    super::unlink_from_parent(&target);
    if let Some(o) = target.mnt_mp.lock().take() { put_mountpoint(&o); }
    super::MOUNTS.lock().remove(&id);
    if let Some(d) = mp.as_ref() {
        super::hash_remove(parent, super::dptr(d), id);
        rewire_crossing_top(ns, d, parent);
    }
    // Lazy-umount deferral (Linux `umount_tree` + `mntput_no_expire`): the mount
    // is now unlinked from the tree (`MNT_DETACHED`). If an external reference
    // still pins it (`mnt_count > 0` — an open file's `f_path.mnt`), DEFER the
    // SB teardown to the final `mntput`; otherwise `put_super` now (flush + drop
    // s_root + clear icache, gated so a sibling sharing the SB blocks teardown).
    target.mark_detached();
    if target.mnt_count() == 0 { super::put_super_if_last(&sb); }
    // Linux `umount_tree`: a detached mount leaves its namespace tree, so drop
    // its slot from `mnt_ns->nr_mounts` (frees cap headroom for a re-mount).
    mntns::dec_mounts(ns, 1);
    mntns::bump_gen(ns);
    1
}

/// Detach EVERY mount whose mountpoint dentry == `d` (pointer identity), in
/// ALL namespaces (Linux `detach_mounts`): invoked from `d_invalidate` when the
/// covered dentry is going away, so any mount(s) overmounting it must be torn
/// down regardless of ns. Cleans crossing/hash/parent-link and `put_super`s the
/// last user of each SB exactly like `unregister`. Returns count removed.
/// # C: O(N_mounts)
pub(crate) fn detach_mounts_on(d: &Arc<Dentry>) -> usize {
    let dp = super::dptr(d);
    let victims: Vec<Arc<Mount>> = super::MOUNTS.lock().values()
        .filter(|m| m.mountpoint().map(|mp| super::dptr(&mp) == dp).unwrap_or(false))
        .cloned().collect();
    let mut removed = 0;
    for m in victims.iter() {
        let ns = m.ns;
        let parent = m.parent_id.load(Ordering::Acquire);
        super::unlink_from_parent(m);
        if let Some(o) = m.mnt_mp.lock().take() { put_mountpoint(&o); }
        super::MOUNTS.lock().remove(&m.mnt_id);
        super::hash_remove(parent, dp, m.mnt_id);
        rewire_crossing_top(ns, d, parent);
        // Detached now (Linux `MNT_DETACHED`); defer SB teardown to the final
        // `mntput` while an external `mnt_count` pin remains.
        m.mark_detached();
        if m.mnt_count() == 0 { super::put_super_if_last(&m.sb); }
        // Linux `umount_tree`: detached from its ns tree → drop a `nr_mounts` slot.
        mntns::dec_mounts(ns, 1);
        mntns::bump_gen(ns);
        removed += 1;
    }
    removed
}

/// Like [`super::descend`] but resolves to the MOUNTPOINT dentry of `rel`'s
/// final component WITHOUT crossing a mount attached there — intermediate
/// components still cross. propagate_umount needs the mirror's mountpoint (so
/// [`unregister`] → `mount_exact_at` finds the mirror mount); a plain `descend`
/// would cross INTO the now-present mirror and return its root, which is not a
/// mountpoint. `rel` empty ⇒ `base`. # C: O(components)
fn descend_mountpoint(base: &Arc<Dentry>, rel: &str) -> Option<Arc<Dentry>> {
    let comps: Vec<&str> = rel.split('/').filter(|c| !c.is_empty()).collect();
    let Some((last, parents)) = comps.split_last() else { return Some(base.clone()); };
    let parent = if parents.is_empty() { base.clone() }
                 else { super::descend(base, &parents.join("/"))? };
    let pinode = parent.inode()?;
    match crate::dcache::d_lookup(&parent, last) {
        Some(d) if !d.is_negative() => Some(d),
        _ => { let ci = pinode.lookup(last).ok()?; Some(crate::dcache::d_add(&parent, last, ci)) }
    }
}

/// Re-point the dentry crossing link to the new hash top after a detach.
/// # C: O(log N)
fn rewire_crossing_top(ns: u64, d: &Arc<Dentry>, parent: u64) {
    match super::hash_top(parent, super::dptr(d)) {
        Some(top) => d.set_mounted_mount(ns, Some(top)),
        None => d.set_mounted_mount(ns, None),
    }
}

/// Detach the top mount at dentry `d`; with `detach_subtree`, also its
/// transitive children. Also propagates the umount to the parent's
/// propagation targets (Linux `propagate_umount`). # C: O(N_mounts)
pub fn unregister_top(d: &Arc<Dentry>, detach_subtree: bool) -> usize {
    let ns = current_ns();
    let Some(top) = mount_exact_at(ns, d) else { return 0; };
    let top_id = top.mnt_id;
    if root_mount_id(ns) == Some(top_id) { return 0; }
    // [D11] A MNT_LOCKED mount cannot be unmounted on its own (Linux
    // `do_umount`: `mnt->mnt_flags & MNT_LOCKED` → -EINVAL): an unprivileged
    // userns must not detach a mount its parent pinned to hide an underlay.
    // Returning 0 (nothing removed) surfaces as EINVAL at the umount2 syscall.
    // A locked submount is still torn down when its PARENT subtree is removed
    // (the per-victim loop below does not re-check the lock).
    if top.is_locked() { return 0; }
    // propagate_umount: detach the mirror at every propagation target of the
    // parent before removing the primary (Linux unmounts propagated copies).
    if let Some(parent) = mount_by_id(top.parent_id.load(Ordering::Acquire)) {
        if let Some(top_mp) = top.mountpoint() {
            if let Some(rel) = rel_under(&top_mp, parent.mountpoint().as_ref()) {
                if !rel.is_empty() {
                    for peer in propagation_targets(&parent) {
                        if peer.ns != ns { continue; }
                        let base = match peer.mountpoint().or_else(global_root) { Some(b) => b, None => continue };
                        // Resolve the mirror's MOUNTPOINT dentry WITHOUT the
                        // final cross: the mirror is mounted there, so a crossing
                        // `descend` would return the mirror ROOT — not a
                        // mountpoint, so `unregister`'s `mount_exact_at` could not
                        // find the mount and the peer mirror would leak.
                        if let Some(mp) = descend_mountpoint(&base, &rel) {
                            let _ = unregister(&mp);
                        }
                    }
                }
            }
        }
    }
    let remove_ids: Vec<u64> = if detach_subtree { super::subtree_ids(ns, top_id) } else { alloc::vec![top_id] };
    let victims: Vec<Arc<Mount>> = remove_ids.iter().filter_map(|id| mount_by_id(*id)).collect();
    let mut removed = 0;
    for m in victims.iter() {
        let parent = m.parent_id.load(Ordering::Acquire);
        let mp = m.mountpoint();
        super::unlink_from_parent(m);
        if let Some(o) = m.mnt_mp.lock().take() { put_mountpoint(&o); }
        super::MOUNTS.lock().remove(&m.mnt_id);
        if let Some(dd) = mp.as_ref() {
            super::hash_remove(parent, super::dptr(dd), m.mnt_id);
            rewire_crossing_top(ns, dd, parent);
        }
        // Lazy-umount deferral (Linux `umount_tree` + `mntput_no_expire`): the
        // victim is now unlinked from the tree (`MNT_DETACHED`). If an external
        // reference still pins it (`mnt_count > 0` — an open file's `f_path.mnt`
        // surviving the lazy umount), DEFER its SB teardown to the final
        // `mntput`; otherwise `put_super` now. Done per-victim AFTER removal so a
        // still-present sibling sharing the SB blocks teardown.
        m.mark_detached();
        if m.mnt_count() == 0 { super::put_super_if_last(&m.sb); }
        // Linux `umount_tree`: each detached victim drops a `nr_mounts` slot.
        mntns::dec_mounts(ns, 1);
        removed += 1;
    }
    mntns::bump_gen(ns);
    removed
}
