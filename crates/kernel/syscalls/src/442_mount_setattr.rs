// 442 mount_setattr — Linux `fs/namespace.c` prepare/commit shape.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec;
use syscall::errno::Errno;
use syscall::SyscallArgs;

use crate::fsmount_common::*;

const PAGE_SIZE: usize = 4096;
const MOUNT_ATTR_SIZE_VER0: usize = 32;

const AT_SYMLINK_NOFOLLOW: u64 = 0x0100;
const AT_NO_AUTOMOUNT: u64 = 0x0800;
const AT_EMPTY_PATH: u64 = 0x1000;
const AT_RECURSIVE: u64 = 0x8000;
const VALID_AT_FLAGS: u64 =
    AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_RECURSIVE;

const MS_UNBINDABLE: u64 = 1 << 17;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SLAVE: u64 = 1 << 19;
const MS_SHARED: u64 = 1 << 20;
const PROPAGATION_MASK: u64 = MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED;

#[derive(Clone, Copy)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

fn neg(error: Errno) -> i64 { -(error.as_i32() as i64) }

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// Linux `copy_struct_from_user`: v0 is exactly 32 bytes, a larger zero tail is
/// accepted, and a nonzero extension byte is `E2BIG`. Size/capability order is
/// observable by feature probes and matches `wants_mount_setattr`.
fn copy_mount_attr(ptr: u64, size: usize) -> Result<MountAttr, i64> {
    if size > PAGE_SIZE { return Err(neg(Errno::E2big)); }
    if size < MOUNT_ATTR_SIZE_VER0 { return Err(neg(Errno::Einval)); }
    if let Some(rv) = may_mount_or_eperm() { return Err(rv); }

    let mut bytes = [0u8; MOUNT_ATTR_SIZE_VER0];
    uaccess::copy_from_user(&mut bytes, ptr).map_err(|_| neg(Errno::Efault))?;
    if size > MOUNT_ATTR_SIZE_VER0 {
        let mut tail = vec![0u8; size - MOUNT_ATTR_SIZE_VER0];
        let tail_ptr = ptr.checked_add(MOUNT_ATTR_SIZE_VER0 as u64)
            .ok_or_else(|| neg(Errno::Efault))?;
        uaccess::copy_from_user(&mut tail, tail_ptr)
            .map_err(|_| neg(Errno::Efault))?;
        if tail.iter().any(|byte| *byte != 0) { return Err(neg(Errno::E2big)); }
    }
    Ok(MountAttr {
        attr_set: u64_at(&bytes, 0),
        attr_clr: u64_at(&bytes, 8),
        propagation: u64_at(&bytes, 16),
        userns_fd: u64_at(&bytes, 24),
    })
}

fn propagation(raw: u64) -> Option<vfs::mount::Propagation> {
    match raw {
        MS_SHARED => Some(vfs::mount::Propagation::Shared),
        MS_SLAVE => Some(vfs::mount::Propagation::Slave),
        MS_UNBINDABLE => Some(vfs::mount::Propagation::Unbindable),
        MS_PRIVATE => Some(vfs::mount::Propagation::Private),
        _ => None,
    }
}

fn validate_attr(attr: &MountAttr) -> Result<(), i64> {
    use vfs::mount::{
        MOUNT_ATTR_IDMAP, MOUNT_ATTR_NOATIME, MOUNT_ATTR_SETTABLE,
        MOUNT_ATTR_STRICTATIME, MOUNT_ATTR__ATIME,
    };
    if attr.propagation & !PROPAGATION_MASK != 0
        || (attr.propagation & PROPAGATION_MASK).count_ones() > 1 {
        return Err(neg(Errno::Einval));
    }
    if (attr.attr_set | attr.attr_clr) & !MOUNT_ATTR_SETTABLE != 0 {
        return Err(neg(Errno::Einval));
    }
    // mount_setattr cannot remove/replace an idmap. That replacement mode is
    // reserved for open_tree_attr(2)'s unpublished clone transaction.
    if attr.attr_clr & MOUNT_ATTR_IDMAP != 0 { return Err(neg(Errno::Einval)); }

    let set_atime = attr.attr_set & MOUNT_ATTR__ATIME;
    let clr_atime = attr.attr_clr & MOUNT_ATTR__ATIME;
    if clr_atime != 0 {
        if clr_atime != MOUNT_ATTR__ATIME { return Err(neg(Errno::Einval)); }
        if set_atime != 0 && set_atime != MOUNT_ATTR_NOATIME
            && set_atime != MOUNT_ATTR_STRICTATIME {
            return Err(neg(Errno::Einval));
        }
    } else if set_atime != 0 {
        return Err(neg(Errno::Einval));
    }
    Ok(())
}

/// Resolve the exact nsfs user-namespace fd, enforce Linux's initial-namespace
/// and namespace-capability gates, then snapshot its canonical maps.
fn idmap_from_fd(fd: u64) -> Result<Arc<vfs::idmap::Idmap>, i64> {
    if fd > i32::MAX as u64 { return Err(neg(Errno::Einval)); }
    let file = fd_file(fd as i32).ok_or_else(|| neg(Errno::Ebadf))?;
    let ns = file.inode().private::<nscg::NsInode>()
        .ok_or_else(|| neg(Errno::Einval))?;
    if ns.kind != nscg::NsKind::User { return Err(neg(Errno::Einval)); }
    let owner = match ns.owner() {
        nscg::NsOwner::User(owner) => owner.clone(),
        _ => return Err(neg(Errno::Einval)),
    };
    if owner.is_initial() { return Err(neg(Errno::Eperm)); }
    let current = sched::live::current().ok_or_else(|| neg(Errno::Eperm))?;
    if !nscg::proc_ns::has_cap_for(current, &owner.pin(), sched::cap::SYS_ADMIN) {
        return Err(neg(Errno::Eperm));
    }
    nscg::user_ns::mount_idmap(&owner)
        .map(Arc::new)
        .map_err(|_| neg(Errno::Einval))
}

fn apply_mount_object(
    object: &MountObjectInode,
    attr: &MountAttr,
    set_mnt: u64,
    clr_mnt: u64,
    idmap: Option<Arc<vfs::idmap::Idmap>>,
    controls_superblock: bool,
    prop: Option<vfs::mount::Propagation>,
    recursive: bool,
) -> i64 {
    let tree = object.detached_tree.lock();
    if let Some(tree) = tree.as_ref() {
        return match vfs::mount::mnt_setattr_detached_tree(
            tree, set_mnt, clr_mnt, idmap, controls_superblock, prop, recursive,
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
    if let Some(map) = idmap {
        if state.idmap.is_some() { return neg(Errno::Eperm); }
        if let Err(error) = vfs::mount::can_idmap_superblock(sb) {
            return crate::namei_common::errno_from_vfs(error);
        }
        if !controls_superblock { return neg(Errno::Eperm); }
        state.idmap = Some(map);
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
    mount_setattr_at(args.a0 as i32, None, args.a1, args.a2, args.a3, args.a4 as usize)
}

/// `mount_setattr(2)` with the pathname optionally already in kernel memory, so
/// `open_tree_attr(2)` can apply the same attribute block to the descriptor it
/// just created without round-tripping a string through userspace. When `path`
/// is `None` the pathname is read from `path_ptr` at exactly the point Linux
/// reads it — AFTER the flag word and the attribute block — so a call that is
/// wrong in both its flags and its pathname pointer still reports the flag
/// error. # C: O(path + selected mounts + userns extents)
pub fn mount_setattr_at(dirfd: i32, path: Option<&str>, path_ptr: u64, at_flags: u64,
                        uattr: u64, size: usize) -> i64 {
    if at_flags & !VALID_AT_FLAGS != 0 { return neg(Errno::Einval); }
    let attr = match copy_mount_attr(uattr, size) {
        Ok(attr) => attr,
        Err(rv) => return rv,
    };
    // Linux returns success for a no-op before looking up either path or
    // userns_fd. A zero-sized support probe was rejected above, as intended.
    if attr.attr_set == 0 && attr.attr_clr == 0 && attr.propagation == 0 {
        return 0;
    }
    if let Err(rv) = validate_attr(&attr) { return rv; }

    let idmap = if attr.attr_set & vfs::mount::MOUNT_ATTR_IDMAP != 0 {
        match idmap_from_fd(attr.userns_fd) {
            Ok(map) => Some(map),
            Err(rv) => return rv,
        }
    } else {
        None
    };
    // Every superblock currently carries the initial filesystem idmapping
    // (the same invariant used by `Mount::may_suid`). Linux checks
    // `ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)` after filesystem admission.
    let controls_superblock = crate::mount_perm::cap_sys_admin_in_init_user_ns();
    let prop = propagation(attr.propagation);
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
    let recursive = at_flags & AT_RECURSIVE != 0;

    if raw_path.is_empty() && at_flags & AT_EMPTY_PATH != 0 {
        if let Some(inode) = fd_inode(dirfd) {
            if let Some(object) = inode.private::<MountObjectInode>() {
                return apply_mount_object(
                    object, &attr, set_mnt, clr_mnt, idmap, controls_superblock,
                    prop, recursive,
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

    if idmap.is_some() {
        let Some(mount) = vfs::mount::mount_by_id(path.mnt_id) else {
            return neg(Errno::Einval);
        };
        if !mount.idmap().is_identity() { return neg(Errno::Eperm); }
        if let Err(error) = vfs::mount::can_idmap_superblock(mount.sb()) {
            return crate::namei_common::errno_from_vfs(error);
        }
        if !controls_superblock { return neg(Errno::Eperm); }
        // Linux `can_idmap_mount`: a mount already visible in the hierarchy
        // cannot acquire its first idmap.
        return neg(Errno::Einval);
    }
    match vfs::mount::mnt_setattr_attached(
        path.mnt_id, set_mnt, clr_mnt, prop, recursive,
    ) {
        Ok(()) => 0,
        Err(error) => crate::namei_common::errno_from_vfs(error),
    }
}
