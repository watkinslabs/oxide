// ---------------------------------------------------------------------------
// D24 Stage 1a — recursive open_tree/move_mount replication.
// `open_tree(OPEN_TREE_CLONE[, AT_RECURSIVE])` detaches a clone of a mount
// subtree into an fd; `move_mount` later splices it under a target via
// [`commit_tree_hashonly`]. (Post the Stage-1b walk-flip the legacy
// `dentry.mounted_mounts` map is GONE, so the "hash-only" commit is now simply
// the same `(parent_mnt_id, dentry)` strict-hash insert every commit does — the
// distinction it once preserved no longer exists.)
// ---------------------------------------------------------------------------

/// Descend `rel` beneath `base` by PLAIN dentry lookup only — NEVER crossing a
/// mount (unlike [`descend`], which follows the strict mount hash). A hash-only commit
/// positions a cloned submount on the MOUNTPOINT dentry inside the parent
/// clone's fs, so it must NOT cross the ORIGINAL mount stacked at that dentry
/// (e.g. resolving `/proc` under the clone root must land on the `/proc`
/// mountpoint dentry, not cross into the live procfs `s_root`). `rel` empty ⇒
/// `base`. # C: O(components)
fn descend_nocross(base: &Arc<Dentry>, rel: &str) -> Option<Arc<Dentry>> {
    let mut cur = base.clone();
    for comp in rel.split('/').filter(|c| !c.is_empty()) {
        let inode = cur.inode()?;
        let child = match crate::dcache::d_lookup(&cur, comp) {
            Some(d) if !d.is_negative() => d,
            _ => { let ci = inode.lookup(comp).ok()?; crate::dcache::d_add(&cur, comp, ci) }
        };
        cur = child;
    }
    Some(cur)
}

/// `open_tree(OPEN_TREE_CLONE)`: CLONE the mount subtree rooted at `src` into a
/// DETACHED node list (UNLINKED from the live tree — no mountpoint, parent, hash
/// or `MOUNTS` entry). `recursive` (AT_RECURSIVE) ⇒ the whole bindable subtree;
/// else root-only (the surplus clones [`copy_tree`] made are released so their
/// SB active refs balance). The caller stores the result in its mount-object fd
/// and either commits it ([`commit_tree_hashonly`] at `move_mount`) or releases
/// it ([`release_clone_tree`] at fd close). # C: O(N_subtree × depth)
/// Linux `__do_loopback`'s admission ladder, shared by the recursive bind and
/// `open_tree(OPEN_TREE_CLONE)`. Three rungs, in this order — the order is the
/// only observable part when more than one applies:
///
///   1. an UNBINDABLE source is never copied            -> EINVAL
///   2. a source outside the caller's mount namespace   -> EINVAL
///   3. a NON-recursive copy whose source has LOCKED children mounted at or
///      under `base` would reveal what those children cover -> EINVAL
///
/// Rung 3 is skipped for a recursive copy because the locked children come
/// along, still covering. # C: O(children)
pub fn may_clone_mount_tree(src: &Arc<Mount>, base: &Arc<Dentry>, recursive: bool) -> KResult<()> {
    if Propagation::from_u8(src.propagation.load(Ordering::Acquire)) == Propagation::Unbindable {
        return Err(VfsError::Einval);
    }
    if !check_mnt(src) { return Err(VfsError::Einval); }
    if !recursive && locked::has_locked_children(src, base) { return Err(VfsError::Einval); }
    Ok(())
}

pub fn clone_mount_tree(src: &Arc<Mount>, recursive: bool) -> DetachedMountTree {
    let namespace = current_namespace();
    let ns = namespace.id();
    let Some(base_mp) = src.mountpoint().or_else(global_root) else {
        // No base dentry (degenerate): root-only clone with empty rel.
        return DetachedMountTree { source: namespace, nodes: alloc::vec![CloneNode {
            m: clone_mnt(src, CloneType::Private, 0, src, ns), rel: String::new(), mp: None }] };
    };
    let mut nodes = copy_tree(src, &base_mp, CloneType::Private, 0, src, ns, true, None);
    if !recursive && nodes.len() > 1 {
        // Root-only: drop (and release) the children copy_tree cloned.
        let extra = nodes.split_off(1);
        for n in extra.iter() { release_clone(&n.m); }
    }
    DetachedMountTree { source: namespace, nodes }
}

/// Release a DETACHED [`clone_mount_tree`] node list that will NOT be committed
/// (an `open_tree` fd closed without a `move_mount`): drop each clone's SB active
/// ref + master slave link via [`release_clone`], so the SB active count and
/// propagation links stay balanced. # C: O(N × master slaves)
pub fn release_clone_tree(tree: &DetachedMountTree) {
    for node in tree.iter() { release_clone(&node.m); }
}

/// [`commit_tree`] variant (D24 Stage 1a): splice a [`clone_mount_tree`] node
/// list under `dest_base`, inserting each clone into the strict `(parent_mnt_id,
/// dentry)` hash + intrusive parent/child links + the `struct mountpoint`
/// (D_MOUNTED) hold. (Once carried a "skip the legacy crossing map" distinction;
/// that map is now deleted, so this is an ordinary strict-hash commit.)
/// Descendants are positioned by [`descend_nocross`]
/// from the deepest already-committed ancestor clone's `mnt_root` (NOT
/// [`descend`], which would cross the original mount), so a cloned `/proc` lands
/// on the same `/proc` mountpoint dentry as the original — giving a DISTINCT hash
/// key `(clone_root_id, /proc)` that coexists with `(ns_root_id, /proc)`. Returns
/// the count committed. # C: O(N × depth)
pub fn commit_tree_hashonly(tree: DetachedMountTree, dest_base: &Arc<Dentry>) -> usize {
    commit_tree_hashonly_at(tree, dest_base, 0)
}

/// As [`commit_tree_hashonly`] but caller supplies the mount that owns
/// `dest_base`. Required for bind-shared dentries where parent-by-dentry is
/// ambiguous. # C: O(N × depth)
pub fn commit_tree_hashonly_at(tree: DetachedMountTree, dest_base: &Arc<Dentry>, dest_base_mnt: u64) -> usize {
    let namespace = current_namespace();
    let ns = namespace.id();
    let mut committed = 0usize;
    let mut dead: Vec<String> = Vec::new();
    // (rel, mnt_id, mnt_root dentry) of each committed node, to resolve
    // descendants' parent + base without consulting the (un-clobbered) map.
    let mut placed: Vec<(String, u64, Arc<Dentry>)> = Vec::new();
    let DetachedMountTree { source, nodes } = tree;
    'node: for node in nodes.into_iter() {
        let CloneNode { m, rel, mp } = node;
        for d in dead.iter() {
            if rel.starts_with(d.as_str()) { release_clone(&m); continue 'node; }
        }
        let (parent_id, mp_d) = if rel.is_empty() {
            let base_mnt = if dest_base_mnt != 0 { dest_base_mnt } else { parent_by_dentry(ns, dest_base) };
            (base_mnt, dest_base.clone())
        } else {
            // Deepest committed ancestor (longest `rel` that is a path-prefix).
            let chosen = placed.iter()
                .filter(|p| p.0.is_empty()
                    || { let mut s = p.0.clone(); s.push('/'); rel.starts_with(&s) })
                .max_by_key(|p| p.0.len())
                .map(|p| (p.0.clone(), p.1, p.2.clone()));
            let Some((p_rel, p_id, p_root)) = chosen else {
                mark_dead(&mut dead, &rel); release_clone(&m); continue;
            };
            // [D31] same-dentry placement (shared `s_root`); descend fallback.
            let placed_d = mp.clone().or_else(|| {
                let sub = rel[p_rel.len()..].trim_start_matches('/');
                descend_nocross(&p_root, sub)
            });
            match placed_d {
                Some(d) => (p_id, d),
                None => { mark_dead(&mut dead, &rel); release_clone(&m); continue; }
            }
        };
        // RESERVE before any visible state (Linux `count_mounts`).
        let reservation = match mntns::MountReservation::reserve(&namespace, 1) {
            Ok(reservation) => reservation,
            Err(_) => { mark_dead(&mut dead, &rel); release_clone(&m); continue; }
        };
        m.rebind_namespace(&namespace);
        // [D28a] one writer-serialized structural region per node (the sleeping
        // `descend_nocross`/`parent_by_dentry` resolution ran above): MOUNTPOINTS
        // + parent/child links + MOUNTS + MOUNT_HASH mutated atomically.
        {
            let _w = MOUNT_WRITE.lock();
            *m.mountpoint.lock() = Some(mp_d.clone());
            *m.rendered_path.lock() = abs_string(&mp_d);
            m.parent_id.store(parent_id, Ordering::Release);
            // The D_MOUNTED hold — ONE `get_mountpoint` per cloned crossing.
            *m.mnt_mp.lock() = Some(get_mountpoint(&mp_d));
            if let Some(p) = mount_by_id(parent_id) {
                *m.mnt_parent.lock() = Arc::downgrade(&p);
                p.mnt_mounts.lock().push(m.clone());
            }
            mounts_publish(m.clone());
            // Strict (parent,dentry) crossing hash — the single crossing structure.
            hash_insert(parent_id, dptr(&mp_d), m.mnt_id);
        }
        #[cfg(feature = "debug-mnt")]
        mntcreate_log("commit_hashonly", m.mnt_id, parent_id, Some(&mp_d), m.mnt_root().as_ref(), Some(&m.sb));
        reservation.commit();
        let mroot = m.mnt_root().unwrap_or_else(|| mp_d.clone());
        placed.push((rel, m.mnt_id, mroot));
        committed += 1;
    }
    if committed > 0 { mntns::bump_gen(ns); }
    drop(source);
    committed
}
