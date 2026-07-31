// `move_mount(MOVE_MOUNT_BENEATH)` — attach the source UNDER the mount already
// at the target instead of over it.
//
// The point of the flag is an atomic replacement: a caller can slide a new
// filesystem in below the live one and then unmount the live one, so no window
// exists where the mountpoint is uncovered. Structurally it is one swap in the
// `(parent_mnt_id, dentry)` graph:
//
//     before:  P --(D)--> TOP
//     after:   P --(D)--> SRC --(SRC.mnt_root)--> TOP
//
// `SRC` takes over `TOP`'s slot on `P` at dentry `D`, and `TOP` is re-parented
// onto `SRC`'s own root dentry. Every mount that was under `TOP` is untouched:
// they are keyed on `TOP`'s id, which does not change.
//
// Included into `mount.rs` alongside the other engine files, so the private
// graph mutators (`hash_insert` / `hash_remove` / `unlink_from_parent` /
// `set_mountpoint_dentry`) and `MOUNT_WRITE` are in scope.

/// Linux `peers()`: two mounts in the SAME peer group, both shared.
/// # C: O(1)
fn peers(a: &Arc<Mount>, b: &Arc<Mount>) -> bool {
    let pg = a.peer_group.load(Ordering::Acquire);
    pg != 0
        && pg == b.peer_group.load(Ordering::Acquire)
        && is_shared(a) && is_shared(b)
}

/// Linux `propagation_would_overmount(from, to, mp)`: would a mount propagated
/// from `from` land exactly on `to`'s root and therefore cover it?
///
/// Only a SHARED `from` propagates at all; the propagated copy lands on `mp`,
/// so it covers `to` only when `to`'s own root IS `mp`; and it reaches `to`
/// only when `to`, or one of `to`'s masters up the chain, is a peer of `from`.
/// # C: O(master chain)
fn propagation_would_overmount(from: &Arc<Mount>, to: &Arc<Mount>, mp: &Arc<Dentry>) -> bool {
    if !is_shared(from) { return false; }
    match to.mnt_root() {
        Some(root) if Arc::ptr_eq(&root, mp) => {}
        _ => return false,
    }
    let mut cur = Some(to.clone());
    while let Some(m) = cur {
        if peers(from, &m) { return true; }
        cur = m.mnt_master.lock().upgrade();
    }
    false
}

/// Linux `mount_is_ancestor(p1, p2)`: is there a (possibly empty) chain of
/// descent from `p1` down to `p2`? # C: O(depth)
fn mount_is_ancestor(p1: &Arc<Mount>, p2: &Arc<Mount>) -> bool {
    let mut cur = p2.clone();
    loop {
        if cur.mnt_id == p1.mnt_id { return true; }
        let parent = cur.parent_id.load(Ordering::Acquire);
        if parent == cur.mnt_id { return false; }
        match mount_by_id(parent) { Some(p) => cur = p, None => return false }
    }
}

/// Is anything mounted directly ON `m`'s own root (Linux `mnt->overmount`)?
/// A source that is itself covered cannot be slid beneath another mount —
/// the propagation machinery would have to build a shadow copy. # C: O(1)
fn has_overmount(m: &Arc<Mount>) -> bool {
    match m.mnt_root() { Some(root) => __lookup_mnt(m.mnt_id, &root).is_some(), None => false }
}

/// `can_move_mount_beneath` + the `do_move_mount` source rungs that apply, in
/// Linux's order. `top` is the mount currently AT the target (the one the
/// source is going under); the target path must have been a mount root for the
/// caller to reach here. Every rung is EINVAL. # C: O(depth + master chain)
fn can_move_beneath(src: &Arc<Mount>, top: &Arc<Mount>) -> KResult<()> {
    let ns = current_namespace().id();
    // Source rungs (`do_move_mount`): in our namespace, detachable from a
    // parent that is not itself the namespace root, not locked, parent not
    // shared.
    if !check_mnt(src) || !check_mnt(top) { return Err(VfsError::Einval); }
    if root_mount_id(ns) == Some(src.mnt_id) { return Err(VfsError::Einval); }
    if src.is_locked() { return Err(VfsError::Einval); }
    let src_parent = src.parent_id.load(Ordering::Acquire);
    if src_parent == src.mnt_id { return Err(VfsError::Einval); }
    if let Some(p) = mount_by_id(src_parent) {
        if is_shared(&p) { return Err(VfsError::Einval); }
    }
    // Beneath rungs (`can_move_mount_beneath`).
    // The top mount must have a parent — there is no slot to take over
    // otherwise, and the namespace root has none.
    let top_parent_id = top.parent_id.load(Ordering::Acquire);
    if top_parent_id == top.mnt_id { return Err(VfsError::Einval); }
    if root_mount_id(ns) == Some(top.mnt_id) { return Err(VfsError::Einval); }
    if has_overmount(src) { return Err(VfsError::Einval); }
    if mount_is_ancestor(top, src) { return Err(VfsError::Einval); }
    let Some(top_parent) = mount_by_id(top_parent_id) else { return Err(VfsError::Einval); };
    // `do_move_mount`'s ELOOP: the destination parent may not be the source or
    // anything beneath it, or the tree becomes its own ancestor. Distinct errno
    // from the EINVAL rungs, and reachable here because a beneath-move's
    // destination parent is the TOP mount's parent, which can easily be the
    // source itself (`move_mount(/src, /src/inner, BENEATH)`).
    if mount_is_ancestor(src, &top_parent) { return Err(VfsError::Eloop); }
    let Some(mp) = top.mountpoint() else { return Err(VfsError::Einval); };
    // Propagation from the top's parent that would land on the top mount, or on
    // the source, defeats the purpose: the copy would end up covering the very
    // mount the caller asked to expose.
    if propagation_would_overmount(&top_parent, top, &mp) { return Err(VfsError::Einval); }
    if propagation_would_overmount(&top_parent, src, &mp) { return Err(VfsError::Einval); }
    // An unbindable source cannot land under a shared destination parent: the
    // parent's peers would each receive a copy of a mount declared unbindable.
    if is_shared(&top_parent) && tree_contains_unbindable(ns, src.mnt_id) {
        return Err(VfsError::Einval);
    }
    Ok(())
}

/// `move_mount(from, to, MOVE_MOUNT_BENEATH)`: re-seat `from_id` into the slot
/// currently held by the mount at `top_id`, then re-parent that mount onto the
/// source's root. `top_id` is the mount the target path resolved INTO, and the
/// caller has already established that the target path is that mount's root
/// (Linux `path_mounted`). # C: O(depth + master chain)
pub fn move_mount_beneath(from_id: u64, top_id: u64) -> KResult<()> {
    let src = mount_by_id(from_id).ok_or(VfsError::Einval)?;
    let top = mount_by_id(top_id).ok_or(VfsError::Einval)?;
    if src.mnt_id == top.mnt_id { return Err(VfsError::Einval); }
    can_move_beneath(&src, &top)?;

    let ns = src.namespace_id();
    let top_parent_id = top.parent_id.load(Ordering::Acquire);
    let mp = top.mountpoint().ok_or(VfsError::Einval)?;
    let rendered = top.mount_point_str();
    let src_root = src.mnt_root().ok_or(VfsError::Einval)?;
    let src_old_parent = src.parent_id.load(Ordering::Acquire);
    let src_old_mp = src.mountpoint();

    let _w = MOUNT_WRITE.lock();
    // 1) Unhook the source from wherever it was.
    if let Some(d) = &src_old_mp { hash_remove(src_old_parent, dptr(d), from_id); }
    unlink_from_parent(&src);
    // 2) Unhook the top mount from its slot — the source is about to take it.
    hash_remove(top_parent_id, dptr(&mp), top_id);
    unlink_from_parent(&top);
    // 3) The source takes over the slot.
    set_mountpoint_dentry(&src, Some(mp.clone()), rendered.clone());
    src.parent_id.store(top_parent_id, Ordering::Release);
    if let Some(p) = mount_by_id(top_parent_id) {
        *src.mnt_parent.lock() = Arc::downgrade(&p);
        p.mnt_mounts.lock().push(src.clone());
    }
    hash_insert(top_parent_id, dptr(&mp), from_id);
    // 4) The top mount lands on the source's own root — same rendered path,
    //    because it is still reached through the same pathname.
    set_mountpoint_dentry(&top, Some(src_root.clone()), rendered);
    top.parent_id.store(from_id, Ordering::Release);
    *top.mnt_parent.lock() = Arc::downgrade(&src);
    src.mnt_mounts.lock().push(top.clone());
    hash_insert(from_id, dptr(&src_root), top_id);
    drop(_w);
    mntns::bump_gen(ns);
    Ok(())
}
