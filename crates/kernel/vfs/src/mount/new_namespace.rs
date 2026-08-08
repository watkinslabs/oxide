//! `create_new_namespace` — the ONE constructor behind the namespace form of
//! both `fsmount(2)` and `open_tree(2)`.
//!
//! Both syscalls hand back a mount-namespace descriptor holding a tree the
//! caller has just built. They differ ONLY in what goes on top:
//! `fsmount(FSMOUNT_NAMESPACE)` puts a fresh mount over a realized superblock
//! there, `open_tree(OPEN_TREE_NAMESPACE)` puts a copy of an existing mount
//! subtree there. Everything else — who owns the namespace, what its root is,
//! which propagation the copies carry, what gets frozen — is one shape, written
//! once, because two copies of it are two things that can disagree.
//!
//! The SHAPE is the part a naive implementation gets wrong. The new namespace's
//! root is NOT the caller's new tree: it is a COPY of the caller's own namespace
//! root, with the new tree mounted ON TOP of that copy. A namespace whose root
//! IS the new tree resolves `/` to the same filesystem, so the difference only
//! shows when someone unmounts the top — with the copy underneath there is still
//! a root to fall back to, and without it the namespace has nothing left.
//!
//! The second decision is propagation. A caller whose CURRENT user namespace is
//! not the one owning its mount namespace is unprivileged with respect to the
//! mounter of everything it is copying, so the copies are made SLAVE — they
//! receive later propagation from the originals but send none back — and the
//! whole new tree is frozen (`lock_mnt_ns`) so a later remount cannot relax a
//! protection nor an unmount reveal what a node covers.

use super::*;

/// What the caller wants mounted on top of the new namespace's root copy.
pub enum NsMountSource {
    /// `fsmount(FSMOUNT_NAMESPACE)`: a fresh mount over an already-realized
    /// superblock. `lock_flags` is whatever the visibility gate fed back.
    NewSuperblock {
        sb: Arc<SuperBlock>,
        mnt_flags: u64,
        lock_flags: u32,
        idmap: Option<Arc<crate::idmap::Idmap>>,
    },
    /// `open_tree(OPEN_TREE_NAMESPACE)`: a copy of the mount subtree at `base`
    /// inside `src`. `recursive` is `AT_RECURSIVE` — the whole bindable subtree
    /// rather than the one mount.
    Tree { src: Arc<Mount>, base: Arc<Dentry>, recursive: bool },
}

impl NsMountSource {
    /// The dentry that becomes `/` inside the new namespace once the tree is on
    /// top. A namespace a task can be placed into must be able to resolve a
    /// path from its root, so this has to be a directory. # C: O(1)
    fn top_root(&self) -> Option<Arc<Dentry>> {
        match self {
            Self::NewSuperblock { sb, .. } => sb.s_root(),
            Self::Tree { base, .. } => Some(base.clone()),
        }
    }
}

/// Is `d` something a path walk can descend through? # C: O(1)
fn can_lookup(d: &Arc<Dentry>) -> bool {
    d.inode().is_some_and(|i| matches!(i.file_type(), crate::FileType::Directory))
}

/// Does the caller's namespace root carry a LOCKED mount somewhere in the stack
/// above it? If so the copy is locked too, or the copy would be a way to reach
/// what that lock exists to hide. An overmount is a mount whose mountpoint is
/// its parent's own root dentry. # C: O(depth × children)
fn stack_above_is_locked(root: &Arc<Mount>) -> bool {
    let mut cur = root.clone();
    // The stack is finite; the bound stops a corrupted parent/child cycle from
    // spinning here rather than reporting.
    for _ in 0..64 {
        let Some(over) = overmount_of(&cur) else { return false };
        if over.is_locked() { return true; }
        cur = over;
    }
    false
}

/// The mount stacked directly on `m`'s own root dentry, if any. # C: O(children)
fn overmount_of(m: &Arc<Mount>) -> Option<Arc<Mount>> {
    let root = m.mnt_root()?;
    m.mnt_mounts.lock().iter()
        .find(|c| c.mountpoint().is_some_and(|mp| Arc::ptr_eq(&mp, &root)))
        .cloned()
}

/// Build a fresh NAMED mount namespace owned by the caller's user namespace,
/// rooted on a copy of the caller's own namespace root, with `source` mounted on
/// top of that copy. Returns the TOP mount (the one the caller asked for) and
/// the namespace, which the caller MUST hold: nothing else refers to a freshly
/// named namespace, and its teardown is what reaps the mounts inside it.
///
/// A caller with no namespace root has nothing to copy; that is not a shape this
/// can produce, so it is refused rather than silently built a different way.
/// # C: O(N_subtree × depth)
pub fn create_new_namespace(source: NsMountSource) -> KResult<(Arc<Mount>, mntns::MntNamespaceRef)> {
    let top_root = source.top_root().ok_or(VfsError::Einval)?;
    if !can_lookup(&top_root) { return Err(VfsError::Enotdir); }

    let caller = mntns::current_namespace();
    let owner = crate::superblock::mounting_user_ns();
    // The reference's `user_ns != ns->user_ns`: privilege over the namespace
    // being created is not privilege over the tree being copied into it.
    let slave = !namespace_identity::NamespacePin::ptr_eq(&owner, &caller.owner_user_namespace());
    let old_root = mntns::ns_root_id(caller.id()).and_then(mount_by_id).ok_or(VfsError::Einval)?;
    let inherit_lock = stack_above_is_locked(&old_root);

    let ns = mntns::allocate(owner).map_err(|_| VfsError::Enomem)?;
    let ns_root = copy_ns_root(&old_root, &ns, slave)?;
    let mp = ns_root.mnt_root().ok_or(VfsError::Einval)?;

    let top = match source {
        NsMountSource::NewSuperblock { sb, mnt_flags, lock_flags, idmap } =>
            mount_sb_over(sb, mnt_flags, lock_flags, idmap, &ns, &ns_root, &mp, slave)?,
        NsMountSource::Tree { src, base, recursive } =>
            copy_tree_over(&src, &base, recursive, &ns, &ns_root, &mp, slave)?,
    };
    if inherit_lock { top.set_internal_flag(MNT_LOCKED); }
    // Freeze the whole namespace, root copy excluded — it is the one node whose
    // removal reveals nothing, and locking it would make the namespace
    // impossible to take apart at all.
    if slave { locked::lock_mnt_ns(ns.id()); }
    mntns::bump_gen(ns.id());
    Ok((top, ns))
}

/// Copy the caller's namespace root into `ns` and make the copy that
/// namespace's root: self-parent, no mountpoint, rendered at `/`. # C: O(1)
fn copy_ns_root(old_root: &Arc<Mount>, ns: &mntns::MntNamespaceRef, slave: bool)
    -> KResult<Arc<Mount>>
{
    let reservation = mntns::MountReservation::reserve(ns, 1)?;
    let ty = if slave { CloneType::Slave } else { CloneType::Private };
    let copy = clone_mnt(old_root, ty, 0, old_root, ns.id());
    {
        let _w = MOUNT_WRITE.lock();
        copy.parent_id.store(copy.mnt_id, Ordering::Release);
        *copy.mountpoint.lock() = None;
        *copy.rendered_path.lock() = String::from("/");
        mounts_publish(Arc::clone(&copy));
    }
    mntns::ns_set_root(ns.id(), copy.mnt_id);
    reservation.commit();
    Ok(copy)
}

/// `fsmount`'s arm: a fresh mount over `sb`, stacked on the root copy.
/// # C: O(log N)
fn mount_sb_over(sb: Arc<SuperBlock>, mnt_flags: u64, lock_flags: u32,
    idmap: Option<Arc<crate::idmap::Idmap>>, ns: &mntns::MntNamespaceRef,
    ns_root: &Arc<Mount>, mp: &Arc<Dentry>, slave: bool) -> KResult<Arc<Mount>>
{
    let reservation = mntns::MountReservation::reserve(ns, 1)?;
    let mnt_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
    let m = new_mount(sb, String::from("/"), Some(mp.clone()), ns_root.mnt_id, mnt_id, ns.id());
    if mnt_flags != 0 { m.flags.store(mnt_flags & MNT_OPTION_MASK, Ordering::Release); }
    if lock_flags != 0 { m.set_internal_flag(lock_flags); }
    if let Some(map) = idmap { m.install_idmap(map); }
    // The copy the namespace gets is made with the same propagation the root
    // copy is, so the two nodes of the new tree agree.
    if slave { m.propagation.store(Propagation::Slave as u8, Ordering::Release); }

    {
        let _w = MOUNT_WRITE.lock();
        *m.mnt_mp.lock() = Some(get_mountpoint(mp));
        *m.mnt_parent.lock() = Arc::downgrade(ns_root);
        ns_root.mnt_mounts.lock().push(Arc::clone(&m));
        mounts_publish(Arc::clone(&m));
        hash_insert(ns_root.mnt_id, dptr(mp), m.mnt_id);
    }
    reservation.commit();
    Ok(m)
}

/// `open_tree`'s arm: a copy of the subtree at `base`, stacked on the root copy.
/// The admission ladder is the shared one (`may_clone_mount_tree`) — the
/// namespace form copies exactly what the detached form may copy.
/// # C: O(N_subtree × depth)
fn copy_tree_over(src: &Arc<Mount>, base: &Arc<Dentry>, recursive: bool,
    ns: &mntns::MntNamespaceRef, ns_root: &Arc<Mount>, mp: &Arc<Dentry>, slave: bool)
    -> KResult<Arc<Mount>>
{
    may_clone_mount_tree(src, base, recursive)?;
    let base_mp = src.mountpoint().or_else(global_root).unwrap_or_else(|| base.clone());
    let ty = if slave { CloneType::Slave } else { CloneType::Private };
    let mut nodes = copy_tree(src, &base_mp, ty, 0, src, ns.id(), true, None);
    if nodes.is_empty() { return Err(VfsError::Einval); }
    if !recursive && nodes.len() > 1 {
        for n in nodes.split_off(1).iter() { release_clone(&n.m); }
    }
    let top = Arc::clone(&nodes[0].m);
    if commit_tree(nodes, mp, ns_root.mnt_id, None, ns.id()) == 0 { return Err(VfsError::Einval); }
    Ok(top)
}
