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

/// `pivot_root(new_root, put_old)` (`docs/16§6`). # C: O(N_mounts × depth)
pub fn pivot_root(new_root: &Arc<Dentry>, put_old: &Arc<Dentry>) -> KResult<()> {
    let ns = current_ns();
    let nr_m = mount_exact_at(ns, new_root).ok_or(VfsError::Einval)?;
    let nr_mp = nr_m.mountpoint();
    let nr_id = nr_m.mnt_id;
    let nr_subtree = subtree_ids(ns, nr_id);
    let po_d = put_old.clone();
    // Mount `put_old` resides on. It must live inside the new-root subtree
    // (Linux pivot_root requirement), so seed it mount-aware from there; this
    // pins the otherwise-ambiguous containing mount when the new tree shares an
    // `s_root` with the old (Stage 1). Fall back to the dentry scan otherwise.
    let po_mnt = mount_owning_dentry_in(&po_d, &nr_subtree)
        .unwrap_or_else(|| containing_mount_id(ns, &po_d));
    let old_root_id = root_mount_id(ns);
    // [D20] Linux `pivot_root(2)` safety checks (all -EINVAL):
    //   * the new_root mount must not be MNT_LOCKED
    //     (`new_mnt->mnt.mnt_flags & MNT_LOCKED`);
    //   * none of {the mount put_old resides on, the new_root's parent, the
    //     current root's parent} may be SHARED — a shared mountpoint would
    //     corrupt its peers when the re-root mutates it
    //     (`IS_MNT_SHARED(old_mnt) || IS_MNT_SHARED(new_mnt->mnt_parent) ||
    //       IS_MNT_SHARED(root_mnt->mnt_parent)`).
    if nr_m.is_locked() { return Err(VfsError::Einval); }
    if let Some(p) = mount_by_id(nr_m.parent_id.load(Ordering::Acquire)) {
        if is_shared(&p) { return Err(VfsError::Einval); }
    }
    if let Some(rm) = old_root_id.and_then(mount_by_id) {
        if let Some(rp) = mount_by_id(rm.parent_id.load(Ordering::Acquire)) {
            if is_shared(&rp) { return Err(VfsError::Einval); }
        }
    }
    if let Some(om) = mount_by_id(po_mnt) {
        if is_shared(&om) { return Err(VfsError::Einval); }
    }
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
        _ if nr_mp.is_none() => rel_under_seeded(&po_d, po_mnt, None).unwrap_or_default(),
        _ => return Err(VfsError::Einval),
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
                set_mountpoint_dentry(m, if is_root { None } else { d.clone() }, p.clone());
            }
        }
        rebuild_ns_index(ns);
    }
    mntns::bump_gen(ns);
}

/// Last-umount teardown (Linux `mntput` → `deactivate_super`): drop THIS
/// mount's active reference on `sb` via the [`SuperBlock`] `s_active` refcount
/// (D6). Each live mount holds exactly one active ref — `for_backend` seeds the
/// first (`s_active == 1`) and every SB-sharing clone (`copy_mnt_ns`, the Linux
/// `clone_mnt` path) grabs one via [`SuperBlock::grab_active`] — so the LAST
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

/// `mntget` (Linux `mntget`): pin a long-lived external reference on `m` — the
/// `f_path.mnt` an open file carries, an in-flight path-walk hold, an fd-based
/// mount handle. Keeps the mount (and, while it is the last detached holder,
/// its superblock) alive across a concurrent lazy umount. Each `mntget` MUST be
/// balanced by exactly one [`mntput`]. # C: O(1)
pub fn mntget(m: &Arc<Mount>) {
    m.mnt_count.fetch_add(1, Ordering::AcqRel);
    // A fresh pin = the mount is in use again: reset its expiry grace so a
    // pending [`mark_mounts_for_expiry`] sweep does not reap it (Linux clears
    // `mnt_expiry_mark` when a mount is referenced).
    m.mnt_internal_flags.fetch_and(!MNT_EXPIRE_MARK, Ordering::AcqRel);
}

/// `mntput` (Linux `mntput_no_expire`): drop a long-lived reference taken by
/// [`mntget`]. When this is the LAST external reference (`mnt_count` 1 → 0) AND
/// the mount was already lazily detached from the tree (`MNT_DETACHED`), run the
/// deferred superblock teardown (`deactivate_super` → `put_super` on the last SB
/// user) — the busy-mount lazy-umount completion. # C: O(1) (O(tree) on last)
pub fn mntput(m: &Arc<Mount>) {
    let prev = m.mnt_count.fetch_sub(1, Ordering::AcqRel);
    hal::kassert!(prev > 0, "mntput: mnt_count underflow below zero");
    if prev == 1 && m.detached.load(Ordering::Acquire) {
        put_super_if_last(&m.sb);
    }
}

/// Unlink `id` from its parent's intrusive child list. # C: O(siblings)
fn unlink_from_parent(m: &Arc<Mount>) {
    if let Some(p) = m.mnt_parent.lock().upgrade() {
        p.mnt_mounts.lock().retain(|c| c.mnt_id != m.mnt_id);
    }
}

/// Copy-on-unshare / `copy_mnt_ns` (`docs/16§6`): clone every mount in
/// `from_ns` into `to_ns` as a fresh independent mount, then rebuild `to_ns`'s
/// index by identity. A child-ns clone of a SHARED mount is demoted to a
/// SLAVE of the source peer group (Linux `copy_mnt_ns` → `CL_SLAVE`), so a
/// later mount in the child does NOT propagate back into the parent ns. The
/// new ns is created. # C: O(N_mounts × depth)
pub fn copy_mnt_ns(from_ns: u64, to_ns: u64) {
    let src = mounts_in_ns(from_ns);
    mntns::ns_get_or_create(to_ns);
    // [D28a] serialize the whole ns clone (the per-clone MOUNTS inserts +
    // NAMESPACES root + the `rebuild_ns_index` link/hash wiring) as one writer
    // region. No `descend` / `put_super` runs here, so no sleep under the lock;
    // `rebuild_ns_index` does NOT self-lock — it is covered by this hold.
    let _w = MOUNT_WRITE.lock();
    for m in src.iter() {
        // [D16] Reuse the shared `clone_mnt` primitive (CL_* fidelity) instead of
        // a hand-rolled inline duplicate: it shares the source SB (one extra
        // `s_active` + kassert), copies the option flags + MNT_LOCKED, and stamps
        // the requested propagation. Per the existing copy_mnt_ns CL_SLAVE
        // demotion, a SHARED source is demoted to a SLAVE of itself (CL_SLAVE: the
        // clone receives parent-ns events but its own mounts stay private to the
        // child ns); every other source is cloned PRIVATE (CL_PRIVATE).
        let prop = Propagation::from_u8(m.propagation.load(Ordering::Acquire));
        let clone = match prop {
            Propagation::Shared => {
                let c = clone_mnt(m, CloneType::Slave, 0, m, to_ns);
                // Keep the source group id on the demoted slave (the slave knows
                // which peer group it slaves to) — the inline path's behaviour.
                c.peer_group.store(m.peer_group.load(Ordering::Acquire), Ordering::Release);
                c
            }
            _ => clone_mnt(m, CloneType::Private, 0, m, to_ns),
        };
        // Cross-ns clone is 1:1: keep the SAME mountpoint dentry (`clone_mnt`
        // leaves it UNLINKED); `rebuild_ns_index` reparents from it below. The
        // rendered path string is already set by `clone_mnt` (`mount_point_str`).
        *clone.mountpoint.lock() = m.mountpoint();
        // [D25] the clone of the SOURCE ns-root mount becomes the new ns root,
        // identified by the source's self-parent `is_root()` (the clone's own
        // self-parent is stamped later by `rebuild_ns_index`'s `None` arm).
        if m.is_root() { mntns::ns_set_root(to_ns, clone.mnt_id); }
        MOUNTS.lock().insert(clone.mnt_id, clone);
    }
    // Account the cloned mounts into the new ns (Linux `copy_mnt_ns` sums
    // `nr_mounts` over the copied tree). The ns COPY itself is not bounded by
    // `sysctl_mount_max` — only later grafts are — so roll the count straight
    // into the live `nr_mounts` (fresh ns ⇒ `pending == 0`).
    mntns::commit_mounts(to_ns, src.len() as u64);
    rebuild_ns_index(to_ns);
    mntns::bump_gen(to_ns);
}

/// Back-compat alias for the unshare(CLONE_NEWNS) call site. # C: O(N×depth)
pub fn snapshot_ns(from_ns: u64, to_ns: u64) { copy_mnt_ns(from_ns, to_ns); }

/// Reap every mount belonging to `ns` (Linux `free_mnt_ns` at last task
/// exit). Drops the per-ns crossings, the hash, the `struct mountpoint`
/// refcounts, and the global-map entries, and `mntput`s each mount's active
/// reference so a ns-private SB (no peer ns sharing it) runs `put_super` on
/// its last drop. # C: O(N_ns_mounts)
pub(crate) fn reap_ns(ns: u64) {
    let mounts = mounts_in_ns(ns);
    for m in mounts.iter() {
        if let Some(o) = m.mnt_mp.lock().take() { put_mountpoint(&o); }
        m.mnt_mounts.lock().clear();
        MOUNTS.lock().remove(&m.mnt_id);
        // free_mnt_ns → mntput → deactivate_super: drop this mount's active ref.
        put_super_if_last(&m.sb);
    }
    // free_mnt_ns: the whole ns is gone — zero its live mount count so a stale
    // `ns_nr_mounts` read after reap reports 0 (Linux `mnt_ns->nr_mounts` dies
    // with the namespace).
    mntns::dec_mounts(ns, mounts.len() as u64);
    hash_drop_ids(&mounts.iter().map(|m| m.mnt_id).collect::<Vec<_>>());
    mntns::bump_gen(ns);
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
    let ns = current_ns();
    let Some(src_m) = mount_exact_at(ns, src) else { return 0; };
    // Unbindable source root is not cloned (Linux `IS_MNT_UNBINDABLE`, D15).
    if is_unbindable(&src_m) { return 0; }
    // Base mountpoint to capture relative positions against: the source root's
    // own mountpoint, or the global root for the namespace-root source.
    let Some(base_mp) = src_m.mountpoint().or_else(global_root) else { return 0; };
    // Mirror under the TARGET's mounted ROOT, not its bare mountpoint dentry.
    let mut tgt_base = tgt.clone();
    let mut tgt_mnt = containing_mount_id(ns, tgt);
    while let Some(m) = __lookup_mnt(tgt_mnt, &tgt_base) {
        match m.mnt_root() { Some(sr) => { tgt_base = sr; tgt_mnt = m.mnt_id; } None => break }
    }
    // Clone the source's submount SUBTREE (root EXCLUDED — already bound) as
    // private binds, then splice it under the destination base, falling back to
    // the bare `tgt` underlay when the mounted root cannot resolve a slot.
    let nodes = copy_tree(&src_m, &base_mp, CloneType::Private, 0, &src_m, ns, false, Some(tgt));
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
    let from_m = mount_exact_at(current_ns(), from).ok_or(VfsError::Einval)?;
    move_mount_m(from_m, to, None)
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
    move_mount_m(from_m, to, to_mnt_id)
}

/// Shared MS_MOVE body for both [`move_mount`] variants. `dest_hint` is the
/// destination parent mount id when known from the walk (see
/// [`move_mount_by_id_to`]); `None` falls back to `parent_by_dentry(to)`.
/// # C: O(N × depth)
fn move_mount_m(from_m: Arc<Mount>, to: &Arc<Dentry>, dest_hint: Option<u64>) -> KResult<()> {
    let ns = current_ns();
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
    if !to_root && top_mount_on(ns, to).is_some() { return Err(VfsError::Ebusy); }
    let to_abs = if to_root { String::from("/") } else { abs_string(to) };
    let old_mp = from_m.mountpoint();
    let old_parent = from_m.parent_id.load(Ordering::Acquire);
    let snap: Vec<Arc<Mount>> = subtree_ids(ns, from_id).iter()
        .filter_map(|id| mount_by_id(*id)).collect();

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
    for m in snap.iter() {
        if m.mnt_id == from_id { continue; }
        let Some(child_mp) = m.mountpoint() else { continue; };
        let disp_rel = rel_under(&child_mp, old_mp.as_ref()).unwrap_or_default();
        let new_rendered = if disp_rel.is_empty() { to_abs.clone() }
                           else { alloc::format!("{}{}", to_abs, disp_rel) };
        match old_mp.as_ref().and_then(|omp| plain_rel_under(&child_mp, omp)) {
            Some(rel) => {
                // UNDERLAY child: relocate its mountpoint dentry to the mirrored
                // underlay position beneath `to`, by an underlay descent (NOT
                // crossing the moved root) from `to`. [D28a] the (sleeping)
                // `descend` runs OUTSIDE the writer lock; the two structural
                // mutations (old-crossing drop, new wiring) are each serialized.
                let m_parent = m.parent_id.load(Ordering::Acquire);
                {
                    let _w = MOUNT_WRITE.lock();
                    hash_remove(m_parent, dptr(&child_mp), m.mnt_id);
                }
                let new_d = to_base.as_ref().and_then(|b| descend(b, rel.trim_start_matches('/')));
                let _w = MOUNT_WRITE.lock();
                set_mountpoint_dentry(m, new_d.clone(), new_rendered);
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
                *m.rendered_path.lock() = new_rendered;
            }
        }
    }
    mntns::bump_gen(ns);
    Ok(())
}
