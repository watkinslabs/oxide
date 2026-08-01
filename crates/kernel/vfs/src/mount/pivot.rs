// `pivot_root(2)` tree surgery (`docs/16§6`). The admission LADDER lives in
// [`pivot_check`]; this file owns what happens after it passes.
//
// Linux `path_pivot_root()` operates on the CALLER's root (`get_fs_root`), not
// on the mount namespace root, and it never reassigns `mnt_ns->root`: it swaps
// two attachments — `new_mnt` takes over the slot `root_mnt` occupied under
// `root_parent`, and `root_mnt` is re-attached under the mount `put_old`
// resides on. When the caller chrooted into some mount OTHER than the namespace
// root, that leaves the namespace root — and every task rooted there — alone.
//
// This kernel's namespace root is self-parented (there is no immutable mount
// beneath it), so the caller-root-IS-namespace-root case has no `root_parent`
// slot to hand over; that case re-roots the namespace instead (`commit_retree`)
// and is the only case where `ns_set_root` fires. Both cases run the same
// ladder, transfer MNT_LOCKED the same way, and fire the same `chroot_fs_refs`.

/// The caller's root as `path_pivot_root()` sees it (`get_fs_root(current->fs)`).
/// The syscall shim supplies it because a task's root is a scheduler-owned
/// `fs_struct` field, not something the mount tree can read.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PivotRoot {
    /// `real_mount(root.mnt)`.
    pub mnt_id: u64,
    /// `path_mounted(&root)` — false for a task chrooted into a plain directory.
    pub path_mounted: bool,
}

/// `pivot_root(new_root, put_old)` for a caller whose root is the namespace
/// root. # C: O(N_mounts × depth)
pub fn pivot_root(new_root: &Arc<Dentry>, put_old: &Arc<Dentry>) -> KResult<()> {
    let ns = current_namespace().id();
    let mnt_id = root_mount_id(ns).ok_or(VfsError::Einval)?;
    pivot_root_from(new_root, put_old, PivotRoot { mnt_id, path_mounted: true })
}

/// Linux `where_to_mount(old, …, false)`: `put_old` resolution descends through
/// anything already mounted there, so the old root STACKS on the overmount
/// rather than being refused. Returns the mount `put_old` finally resides on
/// plus the dentry the old root will be attached to. # C: O(stack depth)
fn where_to_mount(mut mnt: u64, d: &Arc<Dentry>) -> (u64, Arc<Dentry>) {
    let mut d = d.clone();
    while let Some(m) = __lookup_mnt(mnt, &d) {
        match m.mnt_root() { Some(r) => { d = r; mnt = m.mnt_id; } None => break }
    }
    (mnt, d)
}

/// Rendered path a mount attached at dentry `d` under mount `parent_id` shows in
/// `/proc/self/mountinfo`: the parent's own rendered path plus `d`'s position
/// INSIDE the parent's filesystem. Resolving the suffix by plain dentry parents
/// (never a global descent) is what keeps bind mounts — which share their source
/// dentries — rendered at the bind location instead of the source location.
/// # C: O(depth)
fn render_under(parent_id: u64, d: &Arc<Dentry>) -> String {
    if let Some(p) = mount_by_id(parent_id) {
        if let Some(proot) = p.mnt_root() {
            if let Some(rel) = plain_rel_under(d, &proot) {
                let base = p.mount_point_str();
                return if rel.is_empty() { base }
                       else if base == "/" { rel }
                       else { alloc::format!("{}{}", base, rel) };
            }
        }
    }
    rendered_path_for(parent_id, d)
}

/// Linux `attach_mnt(mnt, parent, mp)`: set the mountpoint, wire the parent /
/// child links, and publish the `(parent, dentry)` crossing. Caller holds
/// `MOUNT_WRITE`. # C: O(1)
fn attach_at(m: &Arc<Mount>, parent_id: u64, d: &Arc<Dentry>, rendered: String) {
    set_mountpoint_dentry(m, Some(d.clone()), rendered);
    m.parent_id.store(parent_id, Ordering::Release);
    if let Some(p) = mount_by_id(parent_id) {
        *m.mnt_parent.lock() = Arc::downgrade(&p);
        p.mnt_mounts.lock().push(m.clone());
    }
    hash_insert(parent_id, dptr(d), m.mnt_id);
}

/// Linux `umount_mnt(mnt)`: drop the crossing and the parent's child link. The
/// mountpoint dentry itself is left in place for the caller to overwrite.
/// Caller holds `MOUNT_WRITE`. # C: O(N_children)
fn detach_slot(m: &Arc<Mount>) {
    let parent = m.parent_id.load(Ordering::Acquire);
    if let Some(d) = m.mountpoint() { hash_remove(parent, dptr(&d), m.mnt_id); }
    unlink_from_parent(m);
}

/// Re-render every mount at or below `top` from its parent's rendered path.
/// Positions (dentry + parent) are unchanged — they live inside filesystems that
/// travelled with the move (Linux `copy_tree` keeps them) — only the displayed
/// path follows. # C: O(N_subtree × depth)
fn rerender_subtree(ns: u64, top: u64) {
    for id in subtree_ids(ns, top) {
        if id == top { continue; }
        let Some(m) = mount_by_id(id) else { continue; };
        let Some(d) = m.mountpoint() else { continue; };
        let p = m.parent_id.load(Ordering::Acquire);
        *m.rendered_path.lock() = render_under(p, &d);
    }
}

/// MNT_LOCKED travels with the ROOT SLOT, not with the mount (Linux: the new
/// root inherits the old root's lock so an unprivileged user namespace cannot
/// escape a mount its creator pinned, and the displaced old root loses it so it
/// stays umountable under `put_old`). # C: O(1)
fn transfer_root_lock(root_mnt: &Arc<Mount>, new_mnt: &Arc<Mount>) {
    if root_mnt.is_locked() {
        new_mnt.set_internal_flag(MNT_LOCKED);
        root_mnt.clear_internal_flag(MNT_LOCKED);
    }
}

/// `path_pivot_root()`. Runs Linux's full admission ladder ([`pivot_check`])
/// before any mutation, so a rejected call reports the errno Linux reports and
/// in Linux's order; the surgery below is reached only once every check has
/// passed. # C: O(N_mounts × depth)
pub fn pivot_root_from(new_root: &Arc<Dentry>, put_old: &Arc<Dentry>, root: PivotRoot)
    -> KResult<()>
{
    let namespace = current_namespace();
    let ns = namespace.id();
    // `real_mount(new->mnt)` plus `path_mounted(new)`. A `new_root` that names
    // no mount still has an identity — the mount it resides on — and Linux's
    // ladder consults that identity (EBUSY for the caller's own root mount)
    // BEFORE reporting the not-a-mountpoint EINVAL, so resolving it only when
    // something is mounted there would report the wrong errno.
    let (nr_id, new_path_mounted) = match mount_exact_at(ns, new_root) {
        Some(m) => (m.mnt_id, true),
        None => (containing_mount_id(ns, new_root), false),
    };
    let nr_subtree = subtree_ids(ns, nr_id);
    // Mount `put_old` resides on. It must live inside the new-root subtree
    // (Linux pivot_root requirement), so seed it mount-aware from there; this
    // pins the otherwise-ambiguous containing mount when the new tree shares an
    // `s_root` with the old (Stage 1). Fall back to the dentry scan otherwise.
    let po_seed = mount_owning_dentry_in(put_old, &nr_subtree)
        .unwrap_or_else(|| containing_mount_id(ns, put_old));
    let (po_mnt, po_d) = where_to_mount(po_seed, put_old);
    let old_root_id = root.mnt_id;
    let shared_by_id = |id: u64| mount_by_id(id).map(|m| is_shared(&m)).unwrap_or(false);
    let parent_shared = |id: u64| mount_by_id(id)
        .map(|m| shared_by_id(m.parent_id.load(Ordering::Acquire))).unwrap_or(false);
    // The two `is_path_reachable()` rungs start at the new root's own root
    // dentry — `path_mounted(new)` pins `new->dentry` to it — and the walk
    // replaces it with the mountpoint dentry on the first crossing.
    let nr_root_d = mount_by_id(nr_id).and_then(|m| m.mnt_root());
    // `root->dentry` — the caller's root dentry. `path_mounted(&root)` (checked
    // in the ladder) makes it the root mount's own `mnt_root`.
    let root_d = mount_by_id(root.mnt_id).and_then(|m| m.mnt_root());
    let facts = PivotFacts {
        old_mnt_shared:     shared_by_id(po_mnt),
        new_parent_shared:  parent_shared(nr_id),
        root_parent_shared: parent_shared(root.mnt_id),
        root_in_ns:         mount_by_id(root.mnt_id).map(|m| check_mnt(&m)).unwrap_or(false),
        new_in_ns:          mount_by_id(nr_id).map(|m| check_mnt(&m)).unwrap_or(false),
        new_locked:         mount_by_id(nr_id).map(|m| m.is_locked()).unwrap_or(false),
        new_dentry_unlinked: new_root.is_unlinked(),
        new_is_root_mnt:    nr_id == root.mnt_id,
        old_is_root_mnt:    po_mnt == root.mnt_id,
        root_path_mounted:  root.path_mounted,
        new_path_mounted,
        // `mnt_has_parent(new_mnt)`: a mount here is self-parented iff it is the
        // namespace root, and a chrooted caller reaches this rung with the
        // namespace root as `new_root` without tripping the EBUSY above.
        new_has_parent:     mount_by_id(nr_id).map(|m| !m.is_root()).unwrap_or(false),
        // `is_path_reachable(old_mnt, old_mp->m_dentry, new)` — `new->dentry` is
        // the new root mount's own `mnt_root` (`path_mounted(new)`).
        old_reachable_from_new: reachable_from_mount_root(po_mnt, &po_d, nr_id),
        // `is_path_reachable(new_mnt, new->dentry, &root)` — `&root` is the
        // caller's `struct path`, so the target dentry is the CALLER's root
        // dentry, not the namespace root's.
        new_reachable_from_root: match (&nr_root_d, root_d.as_ref()) {
            (Some(nrd), Some(rd)) => path_reachable_from_root(nr_id, nrd, root.mnt_id, rd),
            _ => false,
        },
    };
    if let Err(e) = pivot_check(&facts) {
        #[cfg(feature = "debug-mnt")]
        {
            klog::write_raw(b"[PIVOT-REJECT] errno=");
            klog::write_dec_u64(e as u64);
            klog::write_raw(b" nr_id="); klog::write_dec_u64(nr_id);
            klog::write_raw(b" po_mnt="); klog::write_dec_u64(po_mnt);
            klog::write_raw(b" root_id="); klog::write_dec_u64(root.mnt_id);
            klog::write_raw(b"\n");
        }
        return Err(e);
    }
    let nr_m = mount_by_id(nr_id).ok_or(VfsError::Einval)?;
    let root_m = mount_by_id(root.mnt_id).ok_or(VfsError::Einval)?;
    let po_m = mount_by_id(po_mnt).ok_or(VfsError::Einval)?;
    // A moved mount does not expire automatically (Linux
    // `list_del_init(&new_mnt->mnt_expire)`).
    mnt_expire_remove_any(nr_id);
    if root_m.is_root() {
        // Caller's root IS the namespace root: no `root_parent` slot exists to
        // hand `new_root` — the namespace itself is re-rooted.
        transfer_root_lock(&root_m, &nr_m);
        return retree_whole_ns(ns, &nr_m, &nr_subtree, po_mnt, &po_d, old_root_id);
    }
    relocate_root_mount(ns, &nr_m, &root_m, &po_m, &po_d)
}

/// The chrooted-caller case: swap two attachments and leave the namespace root
/// (and every task rooted at it) alone. # C: O(N_subtree × depth)
fn relocate_root_mount(ns: u64, nr_m: &Arc<Mount>, root_m: &Arc<Mount>, po_m: &Arc<Mount>,
    po_d: &Arc<Dentry>) -> KResult<()>
{
    // `root_mnt` is not self-parented here, so it has both a parent and a
    // mountpoint — the slot `new_root` takes over.
    let root_parent = root_m.parent_id.load(Ordering::Acquire);
    let root_mp = root_m.mountpoint().ok_or(VfsError::Einval)?;
    let root_rendered = root_m.mount_point_str();
    {
        let _w = MOUNT_WRITE.lock();
        // umount_mnt(new_mnt) / umount_mnt(root_mnt): both leave their slots
        // before either is re-attached, so no `(parent, dentry)` key ever holds
        // two claimants.
        detach_slot(nr_m);
        detach_slot(root_m);
        transfer_root_lock(root_m, nr_m);
        // attach_mnt(new_mnt, root_parent, root_mnt->mnt_mp)
        attach_at(nr_m, root_parent, &root_mp, root_rendered);
        // attach_mnt(root_mnt, old_mnt, old_mp) — rendered AFTER the line above
        // because `put_old` lies inside the new root, whose path just changed.
        let dst = render_under(po_m.mnt_id, po_d);
        attach_at(root_m, po_m.mnt_id, po_d, dst);
        // Everything below the relocated root — including the displaced old root
        // now hanging under `put_old` — keeps its position and re-renders.
        rerender_subtree(ns, nr_m.mnt_id);
    }
    mntns::bump_gen(ns);
    // Both mounts named by the call changed position inside `ns` and neither
    // left it: the old root moved under `put_old` and the new root took its
    // slot. Two move records, one per relocated mount.
    notify::fsnotify_mnt_move(ns, root_m.mnt_id);
    notify::fsnotify_mnt_move(ns, nr_m.mnt_id);
    mntns::chroot_fs_refs(root_m.mnt_id, nr_m.mnt_id);
    Ok(())
}

/// The namespace-root case: `new_root` becomes the namespace root and every
/// mount's rendered position is recomputed against it. # C: O(N × depth)
fn retree_whole_ns(ns: u64, nr_m: &Arc<Mount>, nr_subtree: &[u64], po_mnt: u64,
    po_d: &Arc<Dentry>, old_root_id: u64) -> KResult<()>
{
    let nr_id = nr_m.mnt_id;
    let nr_mp = nr_m.mountpoint();
    let mounts = mounts_in_ns(ns);
    // Position of a PRESERVE-set mount under the new root, MOUNT-AWARE: seed the
    // upward walk from the mount's own recorded parent (the fs its mountpoint
    // dentry lives in) so an SB-sharing clone's shared `s_root` does not derail
    // the crossing chain (Stage 1).
    let preserve_rel = |m: &Arc<Mount>| -> Option<String> {
        m.mountpoint().and_then(|d| rel_under_seeded(&d, m.parent_id.load(Ordering::Acquire), nr_mp.as_ref()))
    };
    let stacking = nr_mp.as_ref().map(|d| Arc::ptr_eq(d, po_d)).unwrap_or(false)
        || rel_under_seeded(po_d, po_mnt, nr_mp.as_ref()) == Some(String::new());
    let old_dst = if stacking { String::from("/") } else {
        match rel_under_seeded(po_d, po_mnt, nr_mp.as_ref()) {
            Some(r) if !r.is_empty() => r,
            _ if nr_mp.is_none() => match rel_under_seeded(po_d, po_mnt, None) {
                Some(r) => r,
                None => {
                    #[cfg(feature = "debug-mnt")]
                    klog::write_raw(b"[PIVOT-EINVAL] put_old has no root-relative path\n");
                    return Err(VfsError::Einval);
                }
            },
            _ => {
                #[cfg(feature = "debug-mnt")]
                klog::write_raw(b"[PIVOT-EINVAL] put_old not under new_root (non-stacking)\n");
                return Err(VfsError::Einval);
            }
        }
    };
    let new_paths: Vec<(u64, String)> = mounts.iter().map(|m| {
        let np = if m.mnt_id == nr_id {
            String::from("/")
        } else if nr_subtree.contains(&m.mnt_id) {
            preserve_rel(m).unwrap_or_else(|| m.mount_point_str())
        } else if stacking {
            m.mount_point_str()
        } else if m.mnt_id == old_root_id {
            old_dst.clone()
        } else {
            let abs = m.mountpoint()
                .and_then(|d| rel_under_seeded(&d, m.parent_id.load(Ordering::Acquire), None))
                .unwrap_or_else(|| m.mount_point_str());
            alloc::format!("{}{}", old_dst, abs)
        };
        (m.mnt_id, np)
    }).collect();
    // `attach_mnt(root_mnt, old_mnt, old_mp)`: the displaced old root attaches
    // on the mount `put_old` finally resides on, at THAT mount's root dentry
    // when `put_old` is covered by an overmount (Linux `where_to_mount`).
    commit_retree(ns, &new_paths, Some(nr_id), Some((old_root_id, po_mnt, po_d.clone())));
    notify::fsnotify_mnt_move(ns, old_root_id);
    notify::fsnotify_mnt_move(ns, nr_id);
    mntns::chroot_fs_refs(old_root_id, nr_id);
    Ok(())
}
