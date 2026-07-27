// ---------------------------------------------------------------------------
// copy_tree / clone_mnt / commit_tree — Linux `fs/namespace.c` subtree clone
// (`copy_tree`/`clone_mnt`/`commit_tree`), the structural primitive shared by
// mount propagation (`propagate_mnt`) and the MS_REC recursive bind. A clone
// SHARES the source superblock (one extra `s_active`), copies its option flags
// + MNT_LOCKED, and carries the requested propagation (CL_MAKE_SHARED / CL_SLAVE
// / private). POSITION: a TOP-LEVEL node's slot lives under a DISTINCT
// destination fs, resolved by the crossing-aware resolver (`rel_under` for
// capture, `descend` for placement). A NESTED submount instead lands inside its
// parent clone's fs — and since the clone SHARES the source `s_root` (Stage 1),
// the source submount's mountpoint dentry IS that slot: [D31] `commit_tree`
// adopts it directly (`CloneNode::mp`, Linux `copy_tree`'s `q->mnt_mountpoint =
// dget(p->mnt_mountpoint)`), keeping the no-cross descent only as a fallback.
// `rel_under_seeded` is the same resolver MS_MOVE/pivot_root retain for
// OUT-OF-SUBTREE relocation.
// ---------------------------------------------------------------------------

/// Propagation type stamped on a [`clone_mnt`] copy (Linux `CL_*` clone flags).
#[derive(Clone, Copy)]
pub(super) enum CloneType { MakeShared, Slave, Private }

/// A node of a [`copy_tree`] result: the cloned mount plus its mountpoint
/// position RELATIVE to the copy's base mountpoint (so [`commit_tree`] can
/// `descend` it under any destination base). # C: field
///
/// `mp` (D31): the SOURCE submount's mountpoint DENTRY. Because a `clone_mnt`
/// copy SHARES the source SB and its `s_root` (Stage 1), a NESTED submount's
/// source mountpoint dentry is a live dentry under its parent clone's `mnt_root`
/// — so [`commit_tree`] adopts it DIRECTLY (Linux `copy_tree`'s `q->mnt_mountpoint
/// = dget(p->mnt_mountpoint)` same-dentry placement) instead of re-deriving the
/// slot by a no-cross path descent (which only CONVERGES with it and can fail to
/// re-mint). `None` for a TOP-LEVEL node (its slot lives under a DISTINCT
/// destination fs reached by `descend`, not the source dentry) and degenerate
/// root-only clones.
///
/// `pub` (D24 Stage 1a): an `open_tree(OPEN_TREE_CLONE)` detaches such a node
/// list into its mount-object fd (`MountObjectInode::detached_tree`), and
/// `move_mount` later commits it ([`commit_tree_hashonly`]) or fd-close releases
/// it ([`release_clone_tree`]).
pub struct CloneNode { pub m: Arc<Mount>, pub rel: String, pub mp: Option<Arc<Dentry>> }

/// Detached clone nodes plus the exact source namespace owner retained by fd.
pub struct DetachedMountTree {
    source: mntns::MntNamespaceRef,
    nodes: Vec<CloneNode>,
}

impl core::ops::Deref for DetachedMountTree {
    type Target = [CloneNode];
    fn deref(&self) -> &Self::Target { &self.nodes }
}

/// Linux `clone_mnt`: build a NEW mount over `src`'s backend, copy its option
/// flags + MNT_LOCKED, and stamp the requested propagation. UNLINKED — no
/// mountpoint, parent, hash or `MOUNTS` entry yet (`commit_tree` wires those).
/// MakeShared joins peer group `pg`; Slave chains onto `master`'s slave list;
/// Private stands alone.
///
/// SB handling is Linux's literal `clone_mnt` share (`atomic_inc(&sb->s_active)`):
/// the clone SHARES the source `SuperBlock` — and therefore its `s_root` DENTRY —
/// taking ONE extra active ref ([`SuperBlock::grab_active`]); [`release_clone`] /
/// `put_super_if_last` drop it. `new_mount` derives the clone's `mnt_root` from
/// `sb.s_root()`, so the clone presents the SAME root dentry as `src`. This is
/// identical to the proven `copy_mnt_ns` cross-ns share; the SAME-ns shared-`s_root`
/// ambiguity it introduces (the 203/EXEC executor-pivot floor) is resolved by the
/// Stage-0 PARENT-AWARE derivation in [`commit_tree`] / [`rebuild_ns_index`], not
/// by minting a distinct per-clone `s_root`. # C: O(1)
pub(super) fn clone_mnt(src: &Arc<Mount>, ty: CloneType, pg: u64, master: &Arc<Mount>, ns: u64)
    -> Arc<Mount> {
    let new_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
    // [Stage 1] SHARE the source SB (and its root dentry) with one extra active
    // ref. The source is live in `MOUNTS`, so its SB is active and `grab_active`
    // always succeeds (kassert mirrors `copy_mnt_ns`).
    let sb = src.sb.clone();
    let grabbed = sb.grab_active();
    hal::kassert!(grabbed, "clone_mnt: live source SB must grab an active ref");
    let clone = new_mount(sb, src.mount_point_str(), None, 0, new_id, ns);
    if let Some(root) = src.mnt_root() { *clone.mnt_root.lock() = Some(root); }
    clone.flags.store(src.flags.load(Ordering::Acquire), Ordering::Release);
    // Keep only MNT_LOCKED on the copy (Linux `clone_mnt`); drop transient marks.
    clone.mnt_internal_flags.store(
        src.mnt_internal_flags.load(Ordering::Acquire) & MNT_LOCKED, Ordering::Release);
    match ty {
        CloneType::MakeShared => {
            clone.propagation.store(Propagation::Shared as u8, Ordering::Release);
            clone.peer_group.store(pg, Ordering::Release);
        }
        CloneType::Slave => {
            clone.propagation.store(Propagation::Slave as u8, Ordering::Release);
            *clone.mnt_master.lock() = Arc::downgrade(master);
            master.mnt_slave_list.lock().push(Arc::downgrade(&clone));
        }
        CloneType::Private => {
            clone.propagation.store(Propagation::Private as u8, Ordering::Release);
        }
    }
    #[cfg(feature = "debug-mnt")]
    mntcreate_log("clone", new_id, 0, None, clone.mnt_root().as_ref(), Some(&clone.sb));
    clone
}

/// Release a [`clone_mnt`] copy that will NOT be committed: unlink it from any
/// master's slave list and drop its `SuperBlock` active ref ([`build_sb`]
/// seeded one), so a skipped/failed clone leaves the SB active count and slave
/// links balanced. # C: O(master slaves)
fn release_clone(m: &Arc<Mount>) {
    if let Some(master) = m.mnt_master.lock().upgrade() {
        master.mnt_slave_list.lock()
            .retain(|w| w.upgrade().map(|x| x.mnt_id != m.mnt_id).unwrap_or(false));
    }
    *m.mnt_master.lock() = Weak::new();
    m.sb.deactivate_super();
}

/// Linux `copy_tree`: recursively CLONE the mount subtree at `src` — the root
/// itself when `include_root`, plus every BINDABLE submount whose mountpoint
/// lies under `base_mp` — preserving peer-group / slave relations per `ty`.
/// UNBINDABLE submounts are dropped (Linux `IS_MNT_UNBINDABLE`, D15). Each clone
/// records its position relative to `base_mp` via [`rel_under`] (the crossing
/// resolver handling both in-fs and underlay children) for later `descend`.
/// Returns the clones in PRE-ORDER (parents first), UNLINKED from the live tree.
/// # C: O(N_subtree × depth)
pub(super) fn copy_tree(src: &Arc<Mount>, base_mp: &Arc<Dentry>, ty: CloneType, pg: u64,
                        master: &Arc<Mount>, ns: u64, include_root: bool,
                        exclude: Option<&Arc<Dentry>>) -> Vec<CloneNode> {
    let mut out: Vec<CloneNode> = Vec::new();
    copy_tree_into(src, base_mp, ty, pg, master, ns, include_root, exclude, &mut out);
    out
}

/// Recursive-bind clone list from explicit mount-parent edges. Walks `src`'s
/// OWN subtree via the intrusive `mnt_mounts` child list ([`subtree_ids`], BFS)
/// instead of scanning every mount in `ns` — proportional to the subtree being
/// bound, not to the namespace's total mount count (B1430). # C: O(N_subtree × depth)
pub(super) fn copy_bind_subtree_from_arena(src: &Arc<Mount>, base_mp: &Arc<Dentry>, ns: u64, exclude_id: Option<u64>) -> Vec<CloneNode> {
    let mut out: Vec<CloneNode> = Vec::new();
    let Some(base_rel) = src.mnt_root().and_then(|root| plain_rel_under(base_mp, &root)) else {
        return out;
    };
    for id in subtree_ids(ns, src.mnt_id).into_iter() {
        if id == src.mnt_id { continue; }
        let Some(m) = mount_by_id(id) else { continue; };
        if is_unbindable(&m) { continue; }
        if exclude_id == Some(m.mnt_id) { continue; }
        if exclude_id.map(|ex| mount_under(&m, ex)).unwrap_or(false) { continue; }
        let Some(mp) = m.mountpoint() else { continue; };
        let Some(full_rel) = bind_rel_under_mount(&m, src.mnt_id) else { continue; };
        let rel = if base_rel.is_empty() {
            full_rel
        } else {
            let prefix = alloc::format!("{}/", base_rel);
            match full_rel.strip_prefix(prefix.as_str()) {
                Some(s) if !s.is_empty() => String::from(s),
                _ => continue,
            }
        };
        if rel.is_empty() { continue; }
        out.push(CloneNode { m: clone_mnt(&m, CloneType::Private, 0, src, ns), rel, mp: Some(mp) });
    }
    out.sort_by_key(|n| n.rel.len());
    out
}

fn mount_under(m: &Arc<Mount>, top: u64) -> bool {
    let mut id = m.parent_id.load(Ordering::Acquire);
    for _ in 0..64 {
        if id == top { return true; }
        let Some(p) = mount_by_id(id) else { break; };
        let next = p.parent_id.load(Ordering::Acquire);
        if next == id { break; }
        id = next;
    }
    false
}

fn bind_rel_under_mount(m: &Arc<Mount>, top: u64) -> Option<String> {
    let mut comps: Vec<String> = Vec::new();
    let mut cur = m.clone();
    for _ in 0..64 {
        let parent = cur.parent_id.load(Ordering::Acquire);
        if parent == cur.mnt_id { return None; }
        let mp = cur.mountpoint()?;
        let parent_root = mount_by_id(parent)?.mnt_root()?;
        let seg = plain_rel_under(&mp, &parent_root)?;
        if seg.is_empty() { return None; }
        comps.push(seg);
        if parent == top { break; }
        cur = mount_by_id(parent)?;
    }
    if cur.parent_id.load(Ordering::Acquire) != top { return None; }
    comps.reverse();
    Some(comps.join("/"))
}

fn copy_tree_into(src: &Arc<Mount>, base_mp: &Arc<Dentry>, ty: CloneType, pg: u64,
                  master: &Arc<Mount>, ns: u64, include_root: bool,
                  exclude: Option<&Arc<Dentry>>, out: &mut Vec<CloneNode>) {
    if include_root {
        // The copy ROOT is positioned at the destination base (a DISTINCT fs),
        // never via the source dentry → `mp: None` (commit_tree uses `descend`).
        let Some(rel) = src.mountpoint()
            .and_then(|d| rel_under(&d, Some(base_mp)))
            .or_else(|| src.mnt_root().and_then(|r| if Arc::ptr_eq(&r, base_mp) { Some(String::new()) } else { None }))
            else { return; };
        out.push(CloneNode { m: clone_mnt(src, ty, pg, master, ns), rel, mp: None });
    }
    // `src`'s own intrusive child list (Linux `mnt_mounts`) — O(1) per
    // recursion level, not a fresh per-node scan-and-filter of every mount in
    // the namespace (old cost: O(k × N_ns) for a k-node subtree, B1430).
    let children: Vec<Arc<Mount>> = src.mnt_mounts.lock().clone();
    for child in children.iter() {
        if is_unbindable(child) { continue; }                       // D15
        let Some(child_mp) = child.mountpoint() else { continue; };
        // Skip a submount that lives under `exclude` (the recursive-bind DESTINATION):
        // never clone the staging tree into itself, and prune its whole subtree.
        if let Some(ex) = exclude {
            if rel_under(&child_mp, Some(ex)).is_some() { continue; }
        }
        let Some(rel) = rel_under(&child_mp, Some(base_mp)) else { continue; };
        if rel.is_empty() { continue; }
        // [D31] Record the source submount's mountpoint dentry: it is shared into
        // every clone of its parent (Stage 1 `s_root` share), so commit_tree can
        // place this nested clone on it directly (Linux same-dentry placement).
        out.push(CloneNode { m: clone_mnt(child, ty, pg, master, ns), rel, mp: Some(child_mp.clone()) });
        copy_tree_into(child, base_mp, ty, pg, master, ns, false, exclude, out);
    }
}

/// Mark `rel`'s subtree dead so every later [`commit_tree`] node beneath a
/// failed/skipped parent is skipped too. # C: O(1)
fn mark_dead(dead: &mut Vec<String>, rel: &str) {
    let mut p = String::from(rel); p.push('/'); dead.push(p);
}

/// Linux `commit_tree`: splice a pre-built [`copy_tree`] clone subtree under the
/// destination — root at `dest_base`, each descendant at `descend(dest_base,
/// rel)` (falling back to `fallback` for a degenerate dest whose mounted root
/// cannot resolve the slot). Per node, in pre-order: RESERVE a per-ns slot
/// ([`mntns::count_mounts`]) BEFORE any visible state; take the `struct
/// mountpoint` D_MOUNTED hold ([`get_mountpoint`], EXACTLY ONE per crossing —
/// the refcount-sensitive line); wire intrusive parent/child + crossing-hash
/// links by dentry identity ([`parent_by_dentry`], as [`graft_realized`]);
/// insert into `MOUNTS`; `commit_mounts`. A node that cannot be positioned or
/// fails the cap is SKIPPED with its descendants (their clones' active SB ref +
/// slave link are released via [`release_clone`]) — never half-attached. One
/// [`mntns::bump_gen`] at the end. Returns the count committed. # C: O(N × depth)
pub(super) fn commit_tree(nodes: Vec<CloneNode>, dest_base: &Arc<Dentry>,
                          dest_base_mnt: u64, fallback: Option<&Arc<Dentry>>, ns: u64) -> usize {
    let mut committed = 0usize;
    let mut dead: Vec<String> = Vec::new();
    // [Stage 0] PARENT-AWARE placement (the executor-pivot floor). Track each
    // committed clone's `(rel, mnt_id, mnt_root)` so a descendant derives its
    // PARENT from the clone-tree STRUCTURE (the deepest committed `rel` that is a
    // path-prefix) and its mountpoint from a NO-CROSS descent of that parent
    // clone's own `mnt_root` — NEVER a dentry-ptr scan (`parent_by_dentry`) nor a
    // crossing `descend` seeded by `containing_mount_id`, both of which an
    // SB-sharing clone (a shared `s_root`, Stage 1) conflates with the SOURCE
    // mount that owns the same dentry. Mirrors [`commit_tree_hashonly`].
    let mut placed: Vec<(String, u64, Arc<Dentry>)> = Vec::new();
    // Parent of a TOP-LEVEL node (no committed ancestor): the mount that owns
    // `dest_base`, supplied explicitly by the caller (the `(parent,dentry)`-known
    // path). `0` ⇒ derive it by dentry scan (callers without shared-`s_root`
    // ambiguity, e.g. propagation onto a distinct peer dentry).
    let base_mnt = if dest_base_mnt != 0 { dest_base_mnt } else { parent_by_dentry(ns, dest_base) };
    'node: for node in nodes.into_iter() {
        let CloneNode { m, rel, mp } = node;
        for d in dead.iter() {
            if rel.starts_with(d.as_str()) { release_clone(&m); continue 'node; }
        }
        // Deepest already-committed ancestor clone (longest `rel` path-prefix).
        let chosen = placed.iter()
            .filter(|p| p.0.is_empty()
                || { let mut s = p.0.clone(); s.push('/'); rel.starts_with(&s) })
            .max_by_key(|p| p.0.len())
            .map(|p| (p.0.clone(), p.1, p.2.clone()));
        let (parent_id, mp_d) = match chosen {
            Some((p_rel, p_id, p_root)) => {
                // [D31] Linux `copy_tree` same-dentry placement: the parent clone
                // SHARES the source parent's SB (Stage 1), so the recorded source
                // mountpoint dentry (`mp`) IS a live slot under the parent clone's
                // `mnt_root` — adopt it directly (`q->mnt_mountpoint =
                // dget(p->mnt_mountpoint)`). Fall back to a no-cross descent of the
                // rel SUFFIX (which only CONVERGES with `mp`) for a degenerate node
                // that recorded none.
                let placed_d = mp.clone().or_else(|| {
                    let sub = rel[p_rel.len()..].trim_start_matches('/');
                    descend_nocross(&p_root, sub)
                });
                match placed_d {
                    Some(d) => (p_id, d),
                    None => { mark_dead(&mut dead, &rel); release_clone(&m); continue; }
                }
            }
            None if rel.is_empty() => (base_mnt, dest_base.clone()),
            None => {
                // Top-level node beneath `dest_base` (the mounted root at the
                // bind target), falling back to the bare `fallback` underlay when
                // the mounted root cannot resolve the slot.
                let sub = rel.trim_start_matches('/');
                let resolved = descend_nocross(dest_base, sub).or_else(|| fallback.and_then(|f| {
                    if Arc::ptr_eq(f, dest_base) { None } else { descend_nocross(f, sub) }
                }));
                match resolved {
                    Some(d) => (base_mnt, d),
                    None => { mark_dead(&mut dead, &rel); release_clone(&m); continue; }
                }
            }
        };
        // RESERVE before any visible state (Linux `count_mounts` in
        // `attach_recursive_mnt`); over the per-ns cap ⇒ skip this node+subtree.
        if mntns::count_mounts(ns, 1).is_err() { mark_dead(&mut dead, &rel); release_clone(&m); continue; }
        let rendered = rendered_path_for(parent_id, &mp_d);
        let mnt_root = m.mnt_root();
        // [D28a] one writer-serialized structural region per node (after the
        // sleeping `descend_nocross` resolved `mp_d` above): parent/child links +
        // MOUNTPOINTS + MOUNTS + MOUNT_HASH mutated atomically w.r.t. other
        // writers. The (sleeping) descent stays OUTSIDE.
        {
            let _w = MOUNT_WRITE.lock();
            *m.mountpoint.lock() = Some(mp_d.clone());
            *m.rendered_path.lock() = rendered;
            m.parent_id.store(parent_id, Ordering::Release);
            // The D_MOUNTED hold — ONE `get_mountpoint` per cloned crossing.
            *m.mnt_mp.lock() = Some(get_mountpoint(&mp_d));
            if let Some(p) = mount_by_id(parent_id) {
                *m.mnt_parent.lock() = Arc::downgrade(&p);
                p.mnt_mounts.lock().push(m.clone());
            }
            mounts_publish(m.clone());
            hash_insert(parent_id, dptr(&mp_d), m.mnt_id);
        }
        // Record this node for its own descendants' parent-aware placement.
        if let Some(r) = mnt_root { placed.push((rel.clone(), m.mnt_id, r)); }
        #[cfg(feature = "debug-mnt")]
        mntcreate_log("commit", m.mnt_id, parent_id, Some(&mp_d), m.mnt_root().as_ref(), Some(&m.sb));
        mntns::commit_mounts(ns, 1);
        committed += 1;
    }
    if committed > 0 { mntns::bump_gen(ns); }
    committed
}

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
