/// In-place swap of a mount's mountpoint dentry + rendered path + `struct
/// mountpoint` (used by MS_MOVE / pivot_root so the Arc — and every intrusive
/// link to it — stays valid). # C: O(log N)
fn set_mountpoint_dentry(m: &Arc<Mount>, new_d: Option<Arc<Dentry>>, rendered: String) {
    let old = m.mnt_mp.lock().take();
    if let Some(o) = old { put_mountpoint(&o); }
    let newmp = new_d.as_ref().map(get_mountpoint);
    *m.mnt_mp.lock() = newmp;
    *m.mountpoint.lock() = new_d;
    *m.rendered_path.lock() = rendered;
}

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

/// `pivot_root(new_root, put_old)` (`docs/16§6`) for a caller whose root is the
/// namespace root. # C: O(N_mounts × depth)
pub fn pivot_root(new_root: &Arc<Dentry>, put_old: &Arc<Dentry>) -> KResult<()> {
    let ns = current_namespace().id();
    let mnt_id = root_mount_id(ns).ok_or(VfsError::Einval)?;
    pivot_root_from(new_root, put_old, PivotRoot { mnt_id, path_mounted: true })
}

/// `path_pivot_root()`. Runs Linux's full admission ladder ([`pivot_check`])
/// before any mutation, so a rejected call reports the errno Linux reports and
/// in Linux's order; the re-parent below is reached only once every check has
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
    let po_d = put_old.clone();
    // Mount `put_old` resides on. It must live inside the new-root subtree
    // (Linux pivot_root requirement), so seed it mount-aware from there; this
    // pins the otherwise-ambiguous containing mount when the new tree shares an
    // `s_root` with the old (Stage 1). Fall back to the dentry scan otherwise.
    let po_mnt = mount_owning_dentry_in(&po_d, &nr_subtree)
        .unwrap_or_else(|| containing_mount_id(ns, &po_d));
    let old_root_id = Some(root.mnt_id);
    let shared_by_id = |id: u64| mount_by_id(id).map(|m| is_shared(&m)).unwrap_or(false);
    let parent_shared = |id: u64| mount_by_id(id)
        .map(|m| shared_by_id(m.parent_id.load(Ordering::Acquire))).unwrap_or(false);
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
        // The two `is_path_reachable()` calls need the relocation plan below,
        // so they are evaluated after it and reported with the same EINVAL
        // Linux gives — they are the last two rungs of the ladder, so nothing
        // observable is reordered by deferring them.
        old_reachable_from_new: true,
        new_reachable_from_root: true,
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
    let nr_mp = nr_m.mountpoint();
    let mounts = mounts_in_ns(ns);
    // Position of a PRESERVE-set mount under the new root, MOUNT-AWARE: seed the
    // upward walk from the mount's own recorded parent (the fs its mountpoint
    // dentry lives in) so an SB-sharing clone's shared `s_root` does not derail
    // the crossing chain (Stage 1).
    let preserve_rel = |m: &Arc<Mount>| -> Option<String> {
        m.mountpoint().and_then(|d| rel_under_seeded(&d, m.parent_id.load(Ordering::Acquire), nr_mp.as_ref()))
    };
    let stacking = nr_mp.as_ref().map(|d| Arc::ptr_eq(d, &po_d)).unwrap_or(false)
        || rel_under_seeded(&po_d, po_mnt, nr_mp.as_ref()) == Some(String::new());
    if stacking {
        let new_paths: Vec<(u64, String)> = mounts.iter().map(|m| {
            let np = if m.mnt_id == nr_id {
                String::from("/")
            } else if nr_subtree.contains(&m.mnt_id) {
                preserve_rel(m).unwrap_or_else(|| m.mount_point_str())
            } else {
                m.mount_point_str()
            };
            (m.mnt_id, np)
        }).collect();
        commit_retree(ns, &new_paths, Some(nr_id), &nr_subtree);
        if let Some(old) = old_root_id { mntns::chroot_fs_refs(old, nr_id); }
        return Ok(());
    }
    let old_dst = match rel_under_seeded(&po_d, po_mnt, nr_mp.as_ref()) {
        Some(r) if !r.is_empty() => r,
        _ if nr_mp.is_none() => match rel_under_seeded(&po_d, po_mnt, None) {
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
    };
    if top_mount_on(ns, &po_d).is_some() { return Err(VfsError::Ebusy); }
    let new_paths: Vec<(u64, String)> = mounts.iter().map(|m| {
        let np = if m.mnt_id == nr_id {
            String::from("/")
        } else if nr_subtree.contains(&m.mnt_id) {
            preserve_rel(m).unwrap_or_else(|| m.mount_point_str())
        } else if Some(m.mnt_id) == old_root_id {
            old_dst.clone()
        } else {
            let abs = m.mountpoint()
                .and_then(|d| rel_under_seeded(&d, m.parent_id.load(Ordering::Acquire), None))
                .unwrap_or_else(|| m.mount_point_str());
            alloc::format!("{}{}", old_dst, abs)
        };
        (m.mnt_id, np)
    }).collect();
    commit_retree(ns, &new_paths, Some(nr_id), &nr_subtree);
    if let Some(old) = old_root_id { mntns::chroot_fs_refs(old, nr_id); }
    Ok(())
}

/// Commit a whole-namespace path rewrite (pivot_root): re-root the ns, then
/// for each mount mutate its position in place and rebuild the ns index (links
/// + crossings + hash) by identity. Mounts listed in `preserve` (the new root's
/// own subtree) KEEP their existing mountpoint dentry — they live INSIDE the
/// moved filesystems and travel unchanged (Linux `copy_tree`); only their
/// rendered path is re-based. Re-deriving their dentry by a global-path
/// `descend` was the 203/EXEC bug: a bind/clone submount's `s_root` is a
/// DISTINCT dentry the global-root descent NEVER reaches, so the descent
/// re-seated the crossing onto the OLD tree's dentry — after the executor's
/// `pivot_root` the relocated `/usr`,`/lib64` were unreachable from the new
/// root, so `execve(/usr/lib/systemd/systemd-udevd)` ENOENT'd → status 203.
/// Mounts OUTSIDE the new-root subtree (the old root + its tree, relocated
/// under `put_old`) are still reachable from the global root, so their position
/// is materialised by `descend`. # C: O(N×depth)
fn commit_retree(ns: u64, new_paths: &[(u64, String)], new_root_id: Option<u64>, preserve: &[u64]) {
    let mounts = mounts_in_ns(ns);
    // [D24] Drop this ns's strict crossing-hash entries BEFORE re-deriving the
    // relocated (non-preserve) positions: those are materialised by a plain
    // dentry `descend` from the new global root, which must NOT cross the stale
    // crossings (matches the legacy map-clear that ran here). `rebuild_ns_index`
    // re-inserts every crossing from the recorded mountpoint dentries below.
    // [D28a] FRONT structural region (before the sleeping `descend` below):
    // drop the stale crossings + re-root the ns, serialized w.r.t. other writers.
    {
        let _w = MOUNT_WRITE.lock();
        hash_drop_ids(&mounts.iter().map(|m| m.mnt_id).collect::<Vec<_>>());
        if let Some(rid) = new_root_id { mntns::ns_set_root(ns, rid); }
    }
    let root = global_root();
    // The (sleeping) `descend` materialization of relocated positions runs with
    // NO writer lock held.
    let dents: Vec<(u64, String, Option<Arc<Dentry>>)> = new_paths.iter().map(|(id, p)| {
        let is_root = Some(*id) == new_root_id;
        let d = if is_root { None }
                else if preserve.contains(id) { mount_by_id(*id).and_then(|m| m.mountpoint()) }
                else { root.as_ref().and_then(|r| descend(r, p)) };
        (*id, p.clone(), d)
    }).collect();
    // [D28a] BACK structural region: re-seat every mount + rebuild the ns index
    // (links + crossings + hash) as one writer-serialized mutation.
    // `rebuild_ns_index` does NOT self-lock — it is covered by this hold.
    {
        let _w = MOUNT_WRITE.lock();
        for m in mounts.iter() {
            if let Some((_, p, d)) = dents.iter().find(|(id, _, _)| *id == m.mnt_id) {
                let is_root = Some(m.mnt_id) == new_root_id;
                if !preserve.contains(&m.mnt_id) { m.parent_id.store(0, Ordering::Release); }
                set_mountpoint_dentry(m, if is_root { None } else { d.clone() }, p.clone());
            }
        }
        rebuild_ns_index(ns);
    }
    mntns::bump_gen(ns);
}

/// Last-umount teardown (Linux `mntput` → `deactivate_super`): drop THIS
/// mount's active reference on `sb` via the [`SuperBlock`] `s_active` refcount
/// (D6). Each live mount holds exactly one active ref: fill-super construction
/// seeds the first (`s_active == 1`), and every SB-sharing clone (`copy_mnt_ns`,
/// the Linux `clone_mnt` path) grabs one via [`SuperBlock::grab_active`] — so the LAST
/// drop (1 → 0) runs `generic_shutdown_super` (sync_filesystem + `put_super`)
/// exactly once, and a still-mounted sibling/ns-clone keeps the shared instance
/// alive. Replaces the old O(N) `Arc::ptr_eq` mount-table scan, which could not
/// see refs held by mounts already removed from `MOUNTS`. Call AFTER the victim
/// is unlinked so the drop accounts for itself. # C: O(1) (O(tree) on last drop)
pub(super) fn put_super_if_last(sb: &Arc<SuperBlock>) {
    // deactivate_super = atomic_dec_and_test; on the 1→0 transition it runs
    // sync_fs + put_super internally (idempotent once already at 0).
    sb.deactivate_super();
}

/// MS_REC recursive bind (`docs/16§6`): mirror the SUBMOUNTS of the source tree
/// under `tgt` (the source ROOT itself is bound separately by the caller). Linux
/// `copy_tree`+`commit_tree`: each submount is CLONED (sharing its SB, copying
/// flags+MNT_LOCKED) as a PRIVATE bind, UNBINDABLE submounts dropped, the whole
/// subtree spliced under the destination in one engine pass with a single
/// D_MOUNTED hold per crossing. Mirror under the TARGET's mounted ROOT (the bind
/// already covers `tgt`, and a submount's slot lives INSIDE that clone — where
/// namei lands after crossing `tgt`); fall back to the bare `tgt` underlay for a
/// degenerate dest whose mounted root cannot resolve the slot, so a plain-dir
/// recursive bind still mirrors (the NAMESPACE-226 procfs-clone case). # C: O(N×depth)
pub fn bind_submounts_rec(src: &Arc<Dentry>, tgt: &Arc<Dentry>) -> usize {
    bind_submounts_rec_at(None, src, tgt, None)
}

/// As [`bind_submounts_rec`] but the caller supplies the target's containing
/// mount id from the original path walk. Required when `tgt`'s dentry is shared
/// across bind locations and `containing_mount_id` would guess the wrong parent.
/// # C: O(N×depth)
pub fn bind_submounts_rec_under(src: &Arc<Dentry>, tgt: &Arc<Dentry>, tgt_parent_hint: Option<u64>) -> usize {
    bind_submounts_rec_at(None, src, tgt, tgt_parent_hint)
}

/// As [`bind_submounts_rec_under`] but the caller also supplies the source mount
/// id from the source path walk. Required once bind roots preserve their source
/// dentry: a later dentry-only exact lookup can confuse the source root with the
/// just-created bind whose `mnt_root` is the same dentry. # C: O(N×depth)
pub fn bind_submounts_rec_at(src_mnt_hint: Option<u64>, src: &Arc<Dentry>, tgt: &Arc<Dentry>,
    tgt_parent_hint: Option<u64>) -> usize {
    let namespace = current_namespace();
    let ns = namespace.id();
    let src_m = src_mnt_hint.and_then(mount_by_id)
        .or_else(|| global_root().filter(|r| Arc::ptr_eq(r, src))
            .and_then(|_| root_mount_id(ns)).and_then(mount_by_id))
        .or_else(|| mount_exact_at(ns, src));
    let Some(src_m) = src_m else { return 0; };
    // Unbindable source root is not cloned (Linux `IS_MNT_UNBINDABLE`, D15).
    if is_unbindable(&src_m) { return 0; }
    // Mirror under the TARGET's mounted ROOT, not its bare mountpoint dentry.
    let mut tgt_base = tgt.clone();
    let mut tgt_mnt = tgt_parent_hint.unwrap_or_else(|| containing_mount_id(ns, tgt));
    let mut exclude_mnt = None;
    while let Some(m) = __lookup_mnt(tgt_mnt, &tgt_base) {
        exclude_mnt = Some(m.mnt_id);
        match m.mnt_root() { Some(sr) => { tgt_base = sr; tgt_mnt = m.mnt_id; } None => break }
    }
    // Clone the source's submount SUBTREE (root EXCLUDED — already bound) as
    // private binds. If `src` is the mountpoint the caller walked BEFORE
    // crossing into `src_m`, subtree discovery starts at `src_m.mnt_root`
    // (Linux source path after `follow_mount`), not at the covered parent-fs
    // dentry. A caller that already supplied a crossed `struct path` dentry uses
    // that dentry as-is.
    let src_base = match src_m.mountpoint() {
        Some(mp) if Arc::ptr_eq(&mp, src) => src_m.mnt_root().unwrap_or_else(|| src.clone()),
        _ => src.clone(),
    };
    let nodes = copy_bind_subtree_from_arena(&src_m, &src_base, ns, exclude_mnt);
    // `tgt_mnt` is the mount whose `mnt_root` is `tgt_base` — the explicit parent
    // of every top-level cloned submount, threaded so the parent-aware
    // `commit_tree` need not (ambiguously) re-derive it from the shared dentry.
    commit_tree(nodes, &tgt_base, tgt_mnt, Some(tgt), ns)
}

/// `mount(MS_MOVE)`: relocate the mount at dentry `from` (plus its subtree) to
/// dentry `to`. Linux `do_move_mount`/`attach_recursive_mnt`: ONLY the moved
/// root's attachment (`mnt_parent`+`mnt_mountpoint`) changes; every internal
/// mount keeps its mountpoint DENTRY + parent link, since those dentries live
/// inside the moved filesystems and travel WITH them (`copy_tree`). An UNDERLAY
/// child (attached on a dentry beneath `from`'s mountpoint in the SAME fs, not
/// crossed into `from`) instead follows `from` to the mirrored spot under `to`.
/// Re-deriving every internal position via a global-PATH `descend` was the bug:
/// a child INSIDE the moved fs cannot be re-found before the root's new crossing
/// exists (and a shared/singleton `s_root` descends into the underlay), so the
/// child is orphaned and its leaf ENOENTs. # C: O(N × depth)
pub fn move_mount(from: &Arc<Dentry>, to: &Arc<Dentry>) -> KResult<()> {
    let namespace = current_namespace();
    let from_m = mount_exact_at(namespace.id(), from).ok_or(VfsError::Einval)?;
    move_mount_m(from_m, to, None, None)
}

/// As [`move_mount`] but identifies the SOURCE mount by the `mnt_id` the path
/// walk CROSSED INTO (Linux `do_move_mount` keys on `path->mnt`). The MS_MOVE
/// source resolves THROUGH the mount being moved, landing on its (often shared)
/// `s_root`, which `mount_exact_at` cannot map back to a mount — so systemd's
/// `mount_move_root` (`mount(".", "/", MS_MOVE)`, the final pivot of the
/// assembled sandbox root) got EINVAL at step NAMESPACE. # C: O(N × depth)
pub fn move_mount_by_id(from_id: u64, to: &Arc<Dentry>) -> KResult<()> {
    move_mount_by_id_to(from_id, None, to)
}

/// As [`move_mount_by_id`] but the caller supplies the DESTINATION mount id the
/// path walk crossed into (`Some`), instead of re-deriving it from the bare
/// `to` dentry. Required when `to` sits in a BIND mount: bind mounts SHARE the
/// underlying dentries, so `parent_by_dentry(to)` is ambiguous and can resolve
/// to a peer bind (e.g. systemd assembles the sandbox root at
/// `/run/systemd/mount-rootfs` — a bind of `/` — then MS_MOVEs `/sys` onto
/// `/run/systemd/mount-rootfs/sys`, whose `sys` dentry IS the real `/sys`
/// mountpoint dentry). Threading the walked `to_mnt_id` disambiguates.
/// # C: O(N × depth)
pub fn move_mount_by_id_to(from_id: u64, to_mnt_id: Option<u64>, to: &Arc<Dentry>) -> KResult<()> {
    let from_m = mount_by_id(from_id).ok_or(VfsError::Einval)?;
    // [D32] Uniform cross-ns guard: `mount_by_id` is the ns-AGNOSTIC arena
    // lookup, so a by-id handle MUST pass `check_mnt` before any mutation.
    if !check_mnt(&from_m) { return Err(VfsError::Einval); }
    move_mount_m(from_m, to, to_mnt_id, None)
}

/// As [`move_mount_by_id_to`] but preserves the caller's mount-aware target
/// display path. Syscall target resolution owns this string because magic
/// links such as `/proc/self/fd/N` can name a bind-shared mountpoint whose bare
/// dentry path is the source location, not the reached mount-tree location.
/// # C: O(N × depth)
pub fn move_mount_by_id_to_rendered(from_id: u64, to_mnt_id: Option<u64>, to: &Arc<Dentry>, rendered: String) -> KResult<()> {
    let from_m = mount_by_id(from_id).ok_or(VfsError::Einval)?;
    if !check_mnt(&from_m) { return Err(VfsError::Einval); }
    move_mount_m(from_m, to, to_mnt_id, Some(rendered))
}

/// Shared MS_MOVE body for both [`move_mount`] variants. `dest_hint` is the
/// destination parent mount id when known from the walk (see
/// [`move_mount_by_id_to`]); `None` falls back to `parent_by_dentry(to)`.
/// # C: O(N × depth)
fn move_mount_m(from_m: Arc<Mount>, to: &Arc<Dentry>, dest_hint: Option<u64>, dest_rendered: Option<String>) -> KResult<()> {
    let namespace = current_namespace();
    let ns = namespace.id();
    let from_id = from_m.mnt_id;
    let to_root = is_ns_root_dentry(to);
    // Linux `do_move_mount` validation (all -EINVAL). NOTE: moving ONTO `/` is
    // NOT rejected here — systemd `mount_move_root` (`mount(new, "/", MS_MOVE)`
    // then `chroot(".")`) depends on it, and Linux permits overmounting the
    // root this way; only the two checks below are universal:
    //   * cannot move the namespace ROOT mount itself (`!mnt_has_parent(old)`);
    //   * cannot move a mount INTO its own subtree (`for(p=dest;...) if p==old`).
    if root_mount_id(ns) == Some(from_id) { return Err(VfsError::Einval); }
    // [D11] A MNT_LOCKED mount cannot be moved (Linux `do_move_mount`:
    // `attached && (old->mnt.mnt_flags & MNT_LOCKED)` → -EINVAL): an
    // unprivileged userns must not relocate a mount its parent pinned.
    if from_m.is_locked() { return Err(VfsError::Einval); }
    // [D21] Don't move a mount residing in a SHARED parent (Linux
    // `do_move_mount`: `attached && IS_MNT_SHARED(parent)` → -EINVAL): the
    // detach from the old position would otherwise have to propagate to the
    // parent's peer group. The source here is always attached (the ns-root case
    // returned above), so this is the unconditional parent-shared rejection.
    if let Some(p) = mount_by_id(from_m.parent_id.load(Ordering::Acquire)) {
        if is_shared(&p) { return Err(VfsError::Einval); }
    }
    // Destination parent mount: prefer the walked `dest_hint` (unambiguous
    // even when `to` is in a bind mount); else re-derive by dentry identity.
    let dest_pid = if to_root { None } else { Some(dest_hint.unwrap_or_else(|| parent_by_dentry(ns, to))) };
    // [D21] Don't move a tree containing UNBINDABLE mounts onto a SHARED
    // destination (Linux `do_move_mount`: `IS_MNT_SHARED(dest) &&
    // tree_contains_unbindable(old)` → -EINVAL): the dest's peers would receive
    // a propagated copy of a mount declared unbindable.
    if let Some(dp) = dest_pid {
        if let Some(dest) = mount_by_id(dp) {
            if is_shared(&dest) && tree_contains_unbindable(ns, from_id) {
                return Err(VfsError::Einval);
            }
        }
    }
    if let Some(dp0) = dest_pid {
        let mut anc = Some(dp0);
        while let Some(a) = anc {
            if a == from_id { return Err(VfsError::Einval); }
            let Some(am) = mount_by_id(a) else { break; };
            let p = am.parent_id.load(Ordering::Acquire);
            anc = if p == a { None } else { Some(p) };
        }
    }
    if !to_root && dest_pid.and_then(|p| __lookup_mnt(p, to)).is_some() { return Err(VfsError::Ebusy); }
    let to_abs = if to_root { String::from("/") } else { dest_rendered.unwrap_or_else(|| abs_string(to)) };
    let old_abs = from_m.mount_point_str();
    let old_mp = from_m.mountpoint();
    let old_parent = from_m.parent_id.load(Ordering::Acquire);
    let snap: Vec<Arc<Mount>> = subtree_ids(ns, from_id).iter()
        .filter_map(|id| mount_by_id(*id)).collect();
    let mut descendant_plan: Vec<(Arc<Mount>, Arc<Dentry>, String, Option<String>)> = Vec::new();
    for m in snap.iter() {
        if m.mnt_id == from_id { continue; }
        let Some(child_mp) = m.mountpoint() else { continue; };
        let disp_seed = m.parent_id.load(Ordering::Acquire);
        let old_child = m.mount_point_str();
        let disp_rel = if old_child == old_abs {
            Some(String::new())
        } else if let Some(rest) = old_child.strip_prefix(old_abs.as_str()) {
            if rest.starts_with('/') { Some(String::from(rest)) }
            else { rel_under_seeded(&child_mp, disp_seed, old_mp.as_ref()) }
        } else {
            rel_under_seeded(&child_mp, disp_seed, old_mp.as_ref())
        };
        let Some(disp_rel) = disp_rel else { return Err(VfsError::Einval); };
        let new_rendered = if disp_rel.is_empty() { to_abs.clone() }
                           else if to_abs == "/" { disp_rel.clone() }
                           else { alloc::format!("{}{}", to_abs, disp_rel) };
        let underlay_rel = old_mp.as_ref().and_then(|omp| plain_rel_under(&child_mp, omp));
        descendant_plan.push((m.clone(), child_mp, new_rendered, underlay_rel));
    }

    // --- 1) Re-seat the moved ROOT mount (the only attachment that changes). ---
    let new_root_d = if to_root { None } else { Some(to.clone()) };
    // [D28a] writer-serialized ROOT re-seat (no `descend` here): drop the old
    // crossing, unlink, then set the new mountpoint + parent/child links +
    // MOUNT_HASH atomically w.r.t. other writers.
    {
        let _w = MOUNT_WRITE.lock();
        if let Some(d) = &old_mp {
            hash_remove(old_parent, dptr(d), from_id);
        }
        unlink_from_parent(&from_m);
        set_mountpoint_dentry(&from_m, new_root_d.clone(), to_abs.clone());
        match &new_root_d {
            None => {
                from_m.parent_id.store(from_id, Ordering::Release);
                *from_m.mnt_parent.lock() = Weak::new();
            }
            Some(d) => {
                let new_parent = dest_pid.unwrap_or_else(|| parent_by_dentry(ns, d));
                from_m.parent_id.store(new_parent, Ordering::Release);
                if let Some(p) = mount_by_id(new_parent) {
                    *from_m.mnt_parent.lock() = Arc::downgrade(&p);
                    p.mnt_mounts.lock().push(from_m.clone());
                }
                hash_insert(new_parent, dptr(d), from_id);
            }
        }
    }

    // --- 2) Descendants: relocate UNDERLAY children (mirrored beneath `to`);
    //        keep IN-FS children in place (dentry/crossing/parent untouched).
    //        Both get their rendered (display) path re-based onto `to`. ---
    let to_base = new_root_d.clone().or_else(global_root);
    for (m, child_mp, new_rendered, underlay_rel) in descendant_plan.iter() {
        match underlay_rel {
            Some(rel) => {
                // UNDERLAY child: relocate its mountpoint dentry to the mirrored
                // underlay position beneath `to`, by an underlay descent (NOT
                // crossing the moved root) from `to`. [D28a] the (sleeping)
                // `descend` runs OUTSIDE the writer lock; the two structural
                // mutations (old-crossing drop, new wiring) are each serialized.
                let m_parent = m.parent_id.load(Ordering::Acquire);
                {
                    let _w = MOUNT_WRITE.lock();
                    hash_remove(m_parent, dptr(child_mp), m.mnt_id);
                }
                let new_d = to_base.as_ref().and_then(|b| descend(b, rel.trim_start_matches('/')));
                let _w = MOUNT_WRITE.lock();
                set_mountpoint_dentry(m, new_d.clone(), new_rendered.clone());
                unlink_from_parent(m);
                if let Some(d) = &new_d {
                    let np = parent_by_dentry(ns, d);
                    m.parent_id.store(np, Ordering::Release);
                    if let Some(p) = mount_by_id(np) {
                        *m.mnt_parent.lock() = Arc::downgrade(&p);
                        p.mnt_mounts.lock().push(m.clone());
                    }
                    hash_insert(np, dptr(d), m.mnt_id);
                }
            }
            None => {
                // IN-FS child: its mountpoint dentry is inside a moved fs and
                // travels unchanged — only the rendered path follows the move.
                *m.rendered_path.lock() = new_rendered.clone();
            }
        }
    }
    if to_root { mntns::ns_set_root(ns, from_id); }
    mntns::bump_gen(ns);
    Ok(())
}
