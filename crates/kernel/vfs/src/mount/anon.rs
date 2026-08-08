//! Mounts that exist but are in nobody's tree — Linux's ANONYMOUS mount
//! namespace (`alloc_mnt_ns(.., anon=true)`, `anon_ns_root`, `dissolve_on_fput`).
//!
//! `fsmount(2)` has to produce a mount before anyone has said where it goes.
//! The reference does this by creating a real `vfsmount` and putting it in an
//! anonymous namespace: the mount is real in every respect — its own id, its
//! own superblock, its own root — and is simply not in any task's namespace, so
//! no path walk can reach it and `listmount` of a task's namespace cannot see
//! it. `move_mount(2)` later moves it out of that namespace into a real tree;
//! closing the fd first dissolves it instead.
//!
//! The alternative this replaces was to carry `(sb, root)` on the fd and mint a
//! mount only at `move_mount` time. That made the fd not a mount: no id, no
//! mount object, nothing for `statmount` to answer about, and nothing to
//! dissolve if the fd was dropped.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::dentry::Dentry;
use crate::superblock::SuperBlock;
use crate::types::KResult;
use crate::{mntns, VfsError};

// `mount/model.rs` is `include!`d into the parent module, so its items live in
// `super` rather than behind a `model::` path.
use super::{mounts_publish_anon, mounts_unpublish_anon, new_mount_for_anon, Mount, NEXT_MNT_ID};

/// Create a real mount for `sb` in a fresh anonymous namespace (Linux
/// `vfs_create_mount` + `alloc_mnt_ns(anon)` + `mnt_add_to_ns`).
///
/// The mount is its namespace's root and its own parent, exactly as a namespace
/// root is: it has no mountpoint, because it is not mounted ON anything yet.
/// # C: O(log N)
pub fn create_anon_mount(sb: Arc<SuperBlock>, mnt_flags: u64, lock_flags: u32,
    idmap: Option<Arc<crate::idmap::Idmap>>) -> KResult<Arc<Mount>>
{
    create_mount_in_anon_ns(sb, mnt_flags, lock_flags, idmap)
}

/// Create a real mount for `sb` inside a fresh NAMED mount namespace — the
/// namespace `fsmount(FSMOUNT_NAMESPACE)` hands back a descriptor for.
///
/// A thin naming of [`super::create_new_namespace`], which owns the whole shape
/// (root copy, placement, propagation, freezing) so `fsmount` and `open_tree`
/// cannot build two different namespaces. The namespace comes back with the
/// mount because the CALLER has to hold it: unlike the anonymous form, nothing
/// inside retains it, and its teardown is what reaps the mounts.
/// # C: O(log N)
pub fn create_ns_mount(sb: Arc<SuperBlock>, mnt_flags: u64, lock_flags: u32,
    idmap: Option<Arc<crate::idmap::Idmap>>)
    -> KResult<(Arc<Mount>, mntns::MntNamespaceRef)>
{
    super::create_new_namespace(super::NsMountSource::NewSuperblock {
        sb, mnt_flags, lock_flags, idmap,
    })
}

fn create_mount_in_anon_ns(sb: Arc<SuperBlock>, mnt_flags: u64, lock_flags: u32,
    idmap: Option<Arc<crate::idmap::Idmap>>) -> KResult<Arc<Mount>>
{
    // The namespace is owned by the caller's user namespace, as the reference's
    // `alloc_mnt_ns(current->nsproxy->mnt_ns->user_ns, …)` is.
    let owner = mntns::current_namespace().owner_user_namespace();
    let ns = mntns::allocate_anon(owner).map_err(|_| VfsError::Enomem)?;
    let mnt_id = NEXT_MNT_ID.fetch_add(1, Ordering::Relaxed);
    let m = new_mount_for_anon(sb, String::from("/"), mnt_id, ns.id());
    if mnt_flags != 0 { m.flags.store(mnt_flags & super::MNT_OPTION_MASK, Ordering::Release); }
    if lock_flags != 0 { m.set_internal_flag(lock_flags); }
    if let Some(map) = idmap { m.install_idmap(map); }
    mntns::ns_set_root(ns.id(), mnt_id);
    ns.nr_mounts.store(1, Ordering::Release);
    // An ANONYMOUS namespace is referred to by nothing else, so the mount has
    // to hold it or it dies here and reaps the mount with it; `dissolve_anon`
    // cuts that link when the descriptor goes.
    *m.anon_ns.lock() = Some(Arc::clone(&ns));
    mounts_publish_anon(Arc::clone(&m));
    Ok(m)
}

/// Linux `anon_ns_root()`: is `m` still the root of an anonymous namespace?
///
/// False the moment `move_mount` has taken it into a real tree, which is what
/// makes dissolve-on-close safe to call unconditionally from the fd's teardown.
/// # C: O(log N)
pub fn anon_ns_root(m: &Mount) -> bool {
    let ns_id = m.namespace_id();
    let Some(ns) = mntns::ns_by_id(ns_id) else { return false };
    ns.is_anon() && ns.root.load(Ordering::Acquire) == m.mnt_id
}

/// Linux `dissolve_on_fput()`: the fd that held an anonymous mount is going
/// away without anyone having moved it, so the mount and its namespace go too.
/// A mount that has since been grafted is left alone — it is somebody's now.
/// # C: O(log N)
pub fn dissolve_anon(m: &Arc<Mount>) {
    if !anon_ns_root(m) { return; }
    let ns_id = m.namespace_id();
    mounts_unpublish_anon(m.mnt_id);
    mntns::ns_set_root(ns_id, 0);
    // Release the namespace last: its `Drop` reaps whatever is still published
    // under it, and the mount is already out.
    let _ = m.anon_ns.lock().take();
}

/// Move an anonymous mount out of its namespace and into the caller's tree at
/// `mp` (Linux `do_move_mount` with an anonymous source: `attach_recursive_mnt`
/// re-parents the mount and the anonymous namespace is left empty and freed).
///
/// This is what `move_mount(2)` does with an `fsmount(2)` fd. The mount object
/// is the SAME one the fd has been referring to all along — same id, same
/// superblock — so a `statmount` taken before the move and one taken after name
/// one mount, which is the property that makes the id meaningful.
/// # C: O(log N)
pub fn graft_anon_mount_at(m: &Arc<Mount>, mp: Arc<Dentry>, dest_base_mnt: u64) -> KResult<()> {
    if !anon_ns_root(m) { return Err(VfsError::Einval); }
    let namespace = mntns::current_namespace();
    let ns = namespace.id();
    let reservation = mntns::MountReservation::reserve(&namespace, 1)?;
    let parent_id = if dest_base_mnt != 0 { dest_base_mnt } else { super::parent_by_dentry(ns, &mp) };
    // Leave the anonymous namespace's index before joining the caller's: the
    // arena is keyed by id and the per-namespace index by (ns, id), so a mount
    // that is re-published without being unpublished would be in two namespaces
    // at once — the split the single `mounts_publish` entry point exists to
    // prevent.
    let anon_ns_id = m.namespace_id();
    mounts_unpublish_anon(m.mnt_id);
    mntns::ns_set_root(anon_ns_id, 0);
    m.rebind_namespace(&namespace);
    {
        let _w = super::MOUNT_WRITE.lock();
        *m.mountpoint.lock() = Some(mp.clone());
        *m.rendered_path.lock() = super::abs_string(&mp);
        m.parent_id.store(parent_id, Ordering::Release);
        *m.mnt_mp.lock() = Some(super::get_mountpoint(&mp));
        if let Some(p) = super::mount_by_id(parent_id) {
            *m.mnt_parent.lock() = Arc::downgrade(&p);
            p.mnt_mounts.lock().push(Arc::clone(m));
        }
        mounts_publish_anon(Arc::clone(m));
        super::hash_insert(parent_id, super::dptr(&mp), m.mnt_id);
    }
    reservation.commit();
    // The namespace has no mounts left; releasing the last reference reaps it.
    let _ = m.anon_ns.lock().take();
    mntns::bump_gen(ns);
    Ok(())
}
