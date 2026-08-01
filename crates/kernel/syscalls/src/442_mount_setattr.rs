// 442 mount_setattr — Linux `fs/namespace.c` prepare/commit shape.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec;
use syscall::errno::Errno;
use syscall::SyscallArgs;

use crate::fsmount_common::*;
use crate::mount_attr_abi::{
    self, MountAttr, AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_RECURSIVE, AT_SYMLINK_NOFOLLOW,
    MOUNT_ATTR_SIZE_VER0, VALID_AT_FLAGS,
};

fn neg(error: Errno) -> i64 { -(error.as_i32() as i64) }

/// Linux `copy_struct_from_user`: v0 is exactly 32 bytes, a larger zero tail is
/// accepted, and a nonzero extension byte is `E2BIG`. Size/capability order is
/// observable by feature probes and matches `wants_mount_setattr`.
fn copy_mount_attr(ptr: u64, size: usize) -> Result<MountAttr, i64> {
    mount_attr_abi::admit_size(size).map_err(neg)?;
    if let Some(rv) = may_mount_or_eperm() { return Err(rv); }

    let mut bytes = [0u8; MOUNT_ATTR_SIZE_VER0];
    uaccess::copy_from_user(&mut bytes, ptr).map_err(|_| neg(Errno::Efault))?;
    if size > MOUNT_ATTR_SIZE_VER0 {
        let mut tail = vec![0u8; size - MOUNT_ATTR_SIZE_VER0];
        let tail_ptr = ptr.checked_add(MOUNT_ATTR_SIZE_VER0 as u64)
            .ok_or_else(|| neg(Errno::Efault))?;
        uaccess::copy_from_user(&mut tail, tail_ptr)
            .map_err(|_| neg(Errno::Efault))?;
        mount_attr_abi::admit_tail(&tail).map_err(neg)?;
    }
    Ok(MountAttr::decode(&bytes))
}

/// Resolve the exact nsfs user-namespace fd, enforce Linux's initial-namespace
/// and namespace-capability gates, then snapshot its canonical maps. Returns
/// the map alongside the namespace it came from, which the per-mount ladder
/// compares against the superblock's own owning namespace.
fn idmap_from_fd(fd: i32)
    -> Result<(Arc<vfs::idmap::Idmap>, namespace_identity::NamespacePin), i64> {
    let file = fd_file(fd).ok_or_else(|| neg(Errno::Ebadf))?;
    let ns = file.inode().private::<nscg::NsInode>()
        .ok_or_else(|| neg(Errno::Einval))?;
    if ns.kind != nscg::NsKind::User { return Err(neg(Errno::Einval)); }
    let owner = match ns.owner() {
        nscg::NsOwner::User(owner) => owner.clone(),
        _ => return Err(neg(Errno::Einval)),
    };
    if owner.is_initial() { return Err(neg(Errno::Eperm)); }
    let current = sched::live::current().ok_or_else(|| neg(Errno::Eperm))?;
    let pin = owner.pin();
    if !nscg::proc_ns::has_cap_for(current, &pin, sched::cap::SYS_ADMIN) {
        return Err(neg(Errno::Eperm));
    }
    nscg::user_ns::mount_idmap(&owner)
        .map(|map| (Arc::new(map), pin))
        .map_err(|_| neg(Errno::Einval))
}

/// Turn the shaped idmap plan into the map + namespace the transaction needs.
/// The removal plan resolves no descriptor, so a caller clearing an idmap never
/// has its `userns_fd` field looked at. # C: O(userns extents)
fn resolve_idmap(plan: crate::mount_idmap_policy::IdmapPlan, kflags: u32,
                 controls_superblock: bool) -> Result<Option<vfs::mount::IdmapSet>, i64> {
    use crate::mount_idmap_policy::IdmapPlan;
    let (map, userns) = match plan {
        IdmapPlan::Leave => return Ok(None),
        IdmapPlan::Identity => (Arc::new(vfs::idmap::Idmap::identity()), None),
        IdmapPlan::FromUserNsFd(fd) => {
            let (map, pin) = idmap_from_fd(fd)?;
            (map, Some(pin))
        }
    };
    Ok(Some(vfs::mount::IdmapSet {
        map, userns,
        replace: crate::mount_idmap_policy::idmap_replace(kflags),
        controls_superblock,
    }))
}

fn apply_mount_object(
    object: &MountObjectInode,
    attr: &MountAttr,
    set_mnt: u64,
    clr_mnt: u64,
    idmap: Option<vfs::mount::IdmapSet>,
    prop: Option<vfs::mount::Propagation>,
    recursive: bool,
) -> i64 {
    let tree = object.detached_tree.lock();
    if let Some(tree) = tree.as_ref() {
        return match vfs::mount::mnt_setattr_detached_tree(
            tree, set_mnt, clr_mnt, idmap, prop, recursive,
        ) {
            Ok(()) => 0,
            Err(error) => crate::namei_common::errno_from_vfs(error),
        };
    }
    drop(tree);

    // Oxide defers materializing an fsmount's `Mount` until move_mount. Its
    // one state lock is the anonymous-mount prepare/commit serialization.
    let Some((sb, _)) = object.realized.as_ref() else { return neg(Errno::Einval); };
    let mut state = object.mount_state.lock();
    let old = vfs::mount::mount_attr_to_mnt(state.attrs);
    let new = (old & !clr_mnt) | set_mnt;
    if !vfs::mount::can_change_locked_options(old, state.lock_flags, new) {
        return neg(Errno::Eperm);
    }
    if let Some(req) = idmap {
        // The object has never been reachable from a mount namespace, so it is
        // the anonymous case the replace mode exists to serve.
        let facts = vfs::mount::idmap_facts_for(sb, &req, state.idmap.is_some(), true);
        if let Err(error) = vfs::mount::can_idmap_mount(facts) {
            return crate::namei_common::errno_from_vfs(error);
        }
        // The identity map is stored as "no map", so a removal and a mount that
        // never had one are one state rather than two that can disagree.
        state.idmap = if req.map.is_identity() { None } else { Some(req.map) };
    }
    let idmap_bit = vfs::mount::MOUNT_ATTR_IDMAP;
    state.attrs &= !(attr.attr_clr & !idmap_bit);
    state.attrs |= attr.attr_set & !idmap_bit;
    state.propagation = prop.or(state.propagation);
    0
}

/// `sys_mount_setattr(dirfd, path, flags, uattr, size)` — slot 442.
/// # C: O(path + selected mounts + userns extents)
pub fn sys_mount_setattr(args: &SyscallArgs) -> i64 {
    let kflags = crate::mount_idmap_policy::kflags_for_mount_setattr(
        args.a2 & AT_RECURSIVE != 0);
    mount_setattr_at(args.a0 as i32, None, args.a1, args.a2, args.a3, args.a4 as usize, kflags)
}

/// `mount_setattr(2)` with the pathname optionally already in kernel memory, so
/// `open_tree_attr(2)` can apply the same attribute block to the descriptor it
/// just created without round-tripping a string through userspace. When `path`
/// is `None` the pathname is read from `path_ptr` at exactly the point Linux
/// reads it — AFTER the flag word and the attribute block — so a call that is
/// wrong in both its flags and its pathname pointer still reports the flag
/// error.
///
/// `kflags` is the caller's kernel-side attribute mode, which the uapi block
/// cannot carry: `open_tree_attr(2)` on a tree it just cloned may remove or
/// replace an idmap, `mount_setattr(2)` may not.
/// # C: O(path + selected mounts + userns extents)
pub fn mount_setattr_at(dirfd: i32, path: Option<&str>, path_ptr: u64, at_flags: u64,
                        uattr: u64, size: usize, kflags: u32) -> i64 {
    if at_flags & !VALID_AT_FLAGS != 0 { return neg(Errno::Einval); }
    let attr = match copy_mount_attr(uattr, size) {
        Ok(attr) => attr,
        Err(rv) => return rv,
    };
    // Linux returns success for a no-op before looking up either path or
    // userns_fd. A zero-sized support probe was rejected above, as intended.
    if attr.is_nop() { return 0; }
    if let Err(errno) = mount_attr_abi::validate(&attr) { return neg(errno); }

    // The idmap REQUEST is shaped from the block plus the caller's mode before
    // any descriptor is touched, so a removal never reads `userns_fd`.
    let plan = match crate::mount_idmap_policy::build_mount_idmapped(
        attr.attr_set, attr.attr_clr, attr.userns_fd, kflags) {
        Ok(plan) => plan,
        Err(error) => return neg(error),
    };
    // Every superblock currently carries the initial filesystem idmapping
    // (the same invariant used by `Mount::may_suid`), so the capability that
    // governs it is the one held in the initial user namespace.
    let controls_superblock = crate::mount_perm::cap_sys_admin_in_init_user_ns();
    let idmap = match resolve_idmap(plan, kflags, controls_superblock) {
        Ok(idmap) => idmap,
        Err(rv) => return rv,
    };
    let prop = mount_attr_abi::propagation(attr.propagation);
    use vfs::mount::{mount_attr_to_mnt, MNT_ATIME_MODE_MASK, MOUNT_ATTR__ATIME};
    let mut set_mnt = mount_attr_to_mnt(attr.attr_set) & !MNT_ATIME_MODE_MASK;
    let mut clr_mnt = mount_attr_to_mnt(attr.attr_clr) & !MNT_ATIME_MODE_MASK;
    if attr.attr_clr & MOUNT_ATTR__ATIME == MOUNT_ATTR__ATIME {
        clr_mnt |= MNT_ATIME_MODE_MASK;
        set_mnt |= mount_attr_to_mnt(attr.attr_set) & MNT_ATIME_MODE_MASK;
    }

    let owned;
    let raw_path = match path {
        Some(p) => p,
        None => match read_path_allow_empty(path_ptr) {
            Ok(p) => { owned = p; owned.as_str() }
            Err(rv) => return rv,
        },
    };
    let recursive = crate::mount_idmap_policy::recurse(kflags);

    if raw_path.is_empty() && at_flags & AT_EMPTY_PATH != 0 {
        if let Some(inode) = fd_inode(dirfd) {
            if let Some(object) = inode.private::<MountObjectInode>() {
                return apply_mount_object(
                    object, &attr, set_mnt, clr_mnt, idmap, prop, recursive,
                );
            }
        }
    }

    let path = match crate::pathresolve::resolve_at_path(dirfd, raw_path, vfs::LookupFlags {
        empty: at_flags & AT_EMPTY_PATH != 0,
        no_follow_final: at_flags & AT_SYMLINK_NOFOLLOW != 0,
        no_automount: at_flags & AT_NO_AUTOMOUNT != 0,
        ..Default::default()
    }) {
        Ok(path) => path,
        Err(rv) => return rv,
    };
    let mounted = vfs::mount::root_dentry_for_mount_id(path.mnt_id)
        .map(|root| Arc::ptr_eq(&root, &path.dentry)).unwrap_or(false);
    if !mounted { return neg(Errno::Einval); }

    if let Some(req) = idmap.as_ref() {
        let Some(mount) = vfs::mount::mount_by_id(path.mnt_id) else {
            return neg(Errno::Einval);
        };
        // A path lookup landed on it, so it is reachable from a live mount
        // namespace: `anon_ns` is false and the ladder's last rung refuses the
        // change whatever mode the caller is in. Running the whole ladder
        // anyway keeps the EARLIER refusals (second install, unsupported
        // filesystem, missing capability) observable in their real order.
        let already = !mount.idmap().is_identity();
        let facts = vfs::mount::idmap_facts_for(mount.sb(), req, already, false);
        let error = vfs::mount::can_idmap_mount(facts).err().unwrap_or(vfs::VfsError::Einval);
        return crate::namei_common::errno_from_vfs(error);
    }
    match vfs::mount::mnt_setattr_attached(
        path.mnt_id, set_mnt, clr_mnt, prop, recursive,
    ) {
        Ok(()) => 0,
        Err(error) => crate::namei_common::errno_from_vfs(error),
    }
}
