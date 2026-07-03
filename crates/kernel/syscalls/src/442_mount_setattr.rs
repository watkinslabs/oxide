// 442 mount_setattr — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::fsmount_common::*;

/// `sys_mount_setattr(dirfd, path, flags, uattr, size)` — slot 442.
/// Changes mount attributes on the mount at `path`: we honour the propagation
/// change (`mount_attr.propagation` → MS_SHARED/PRIVATE/SLAVE/UNBINDABLE) via
/// `vfs::mount::set_propagation`, AND [D52] the per-mount option bits
/// (`attr_set`/`attr_clr` → RDONLY/NOSUID/NODEV/NOEXEC/atime/NODIRATIME/
/// NOSYMFOLLOW) mapped into the MNT_* space and applied to the mount the walk
/// crossed into (`AT_RECURSIVE` ⇒ the whole subtree). Only MNT_RDONLY has
/// runtime enforcement today (EROFS); the rest are reported via /proc/mounts +
/// statvfs `ST_*`. ID-mapped mounts are not implemented, so requests using
/// `MOUNT_ATTR_IDMAP` are rejected instead of falsely advertising support to
/// systemd. `struct mount_attr` is
/// `{ u64 attr_set, attr_clr, propagation, userns_fd }` (32 bytes).
/// # C: O(N_mounts)
pub fn sys_mount_setattr(args: &SyscallArgs) -> i64 {
    use vfs::mount::Propagation;
    const MS_UNBINDABLE: u64 = 1 << 17;
    const MS_PRIVATE:    u64 = 1 << 18;
    const MS_SLAVE:      u64 = 1 << 19;
    const MS_SHARED:     u64 = 1 << 20;
    const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
    if let Some(rv) = require_sys_admin() { return rv; }  // Linux may_mount (D49)
    // Linux `sys_mount_setattr` order: validate `uattr`/`usize` (copy_mount_setattr)
    // BEFORE resolving `path` (user_path_at is last). So a support-probe
    // `mount_setattr(fd, NULL, 0, NULL, 0)` must return EINVAL (usize < VER0),
    // NOT EFAULT from reading the NULL path — systemd's mount_setattr feature
    // detection keys on EINVAL==supported / ENOSYS==unsupported; EFAULT made it
    // mis-detect and fall back, and diverged from Linux (67× per boot).
    let uattr = args.a3;
    let size  = args.a4 as usize;
    if uattr == 0 || size < 24 || uattr >= USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    if uattr.checked_add(size as u64).map(|end| end > USER_VA_END).unwrap_or(true) {
        return -(Errno::Efault.as_i32() as i64);
    }
    const AT_RECURSIVE: u64 = 0x8000;
    const AT_EMPTY_PATH: u64 = 0x1000;
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    use vfs::mount::{MNT_ATIME_MASK, MOUNT_ATTR_NOATIME, MOUNT_ATTR_SETTABLE,
                     MOUNT_ATTR_STRICTATIME, MOUNT_ATTR__ATIME, mount_attr_to_mnt};
    // SAFETY: uattr+16 is covered by the validated minimum struct size.
    let attr_set = unsafe { core::ptr::read_volatile(uattr as *const u64) };
    // SAFETY: uattr+8 (attr_clr) is within the validated minimum 24-byte struct.
    let attr_clr = unsafe { core::ptr::read_volatile((uattr + 8) as *const u64) };
    if (attr_set & MOUNT_ATTR_IDMAP) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    // Unknown request bits (outside the settable, non-idmap set) → EINVAL, as
    // Linux validates the request mask before `build_mount_kattr`.
    if (attr_set & !MOUNT_ATTR_SETTABLE) != 0 || (attr_clr & !MOUNT_ATTR_SETTABLE) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    // atime sub-field rules (Linux): to change the atime mode the caller must
    // clear the WHOLE MOUNT_ATTR__ATIME field, and the chosen mode in attr_set
    // must be exactly one of relatime(0)/noatime/strictatime.
    let atime_set = attr_set & MOUNT_ATTR__ATIME;
    let atime_clr = attr_clr & MOUNT_ATTR__ATIME;
    if (atime_set | atime_clr) != 0 {
        if atime_clr != MOUNT_ATTR__ATIME { return -(Errno::Einval.as_i32() as i64); }
        if atime_set != 0 && atime_set != MOUNT_ATTR_NOATIME && atime_set != MOUNT_ATTR_STRICTATIME {
            return -(Errno::Einval.as_i32() as i64);
        }
    }
    // Map the request into the per-mount MNT_* option space. Direct bits map
    // one-to-one; the atime mode is only touched when the full sub-field is
    // cleared (else the mount keeps its current atime policy).
    let mut set_mnt = mount_attr_to_mnt(attr_set) & !MNT_ATIME_MASK;
    let mut clr_mnt = mount_attr_to_mnt(attr_clr) & !MNT_ATIME_MASK;
    if atime_clr == MOUNT_ATTR__ATIME {
        clr_mnt |= MNT_ATIME_MASK;                                // clear all 3
        set_mnt |= mount_attr_to_mnt(attr_set) & MNT_ATIME_MASK;  // set chosen
    }
    // NB: `userns_fd` (offset 24) is deliberately NOT inspected. Linux
    // `build_mount_kattr` reads it ONLY inside `if attr_set & MOUNT_ATTR_IDMAP`
    // (rejected just above); for every non-idmap caller it is ignored, whatever
    // its value. libmount/mount(8) zero-initialise `struct mount_attr`, so a
    // mandatory `userns_fd == -1` test wrongly rejected the universal
    // zero-filled struct (EINVAL → mount(8) exit 32 for debugfs/tracefs).
    // Read mount_attr.propagation (third u64, offset 16).
    // SAFETY: uattr+24 ≤ size and < USER_VA_END validated; CPL=0/EL1 reads the u64 through the caller's AS.
    let propagation = unsafe { core::ptr::read_volatile((uattr + 16) as *const u64) };
    let dirfd = args.a0 as i32;
    // DETACHED-object fast path (Linux `mount_setattr` on an fsmount/open_tree fd):
    // systemd 257's per-service mount setup runs fsopen→fsconfig→fsmount→
    // `mount_setattr(fd, "", AT_EMPTY_PATH[|AT_RECURSIVE], {MOUNT_ATTR_RDONLY})`→
    // move_mount. The fd names a `MountObjectInode` NOT yet in any namespace tree,
    // so there is no `path->mnt` to resolve — the attrs must be recorded ON the
    // detached object and applied when `move_mount` attaches it. The old code
    // resolved the empty path string against cwd → the WRONG mount, so the subtree
    // attached read-WRITE; its /proc/self/mountinfo line stayed `rw`, so systemd's
    // `bind_remount_recursive` convergence loop (re-reads mountinfo, retries) never
    // settled, hit its 32-try cap, and returned EBUSY — aborting the whole mount
    // namespace (status 226 for udevd/logind/dbus-broker → no graphical target).
    if (args.a2 & AT_EMPTY_PATH) != 0 {
        if let Some(inode) = fd_inode(dirfd) {
            if let Some(mo) = inode.private::<MountObjectInode>() {
                // A detached clone tree holds real (unlinked) Mount objects — stamp
                // the MNT_* change on each now, so `commit_tree_hashonly` links them
                // already read-only (AT_RECURSIVE ⇒ the whole tree, which this is).
                if let Some(tree) = mo.detached_tree.lock().as_ref() {
                    for node in tree.iter() {
                        vfs::mount::apply_mnt_attrs_detached(&node.m, set_mnt, clr_mnt);
                    }
                }
                // The realized/clone/legacy attach path reads `mnt_attrs` (raw
                // MOUNT_ATTR_* space) at move_mount: fold the request in (clr then set).
                use core::sync::atomic::Ordering;
                mo.mnt_attrs.fetch_and(!attr_clr, Ordering::AcqRel);
                mo.mnt_attrs.fetch_or(attr_set, Ordering::AcqRel);
                return 0;
            }
        }
    }
    // Attached-mount path: resolve `path->mnt` honoring `dirfd` + AT_EMPTY_PATH
    // (Linux `user_path_at(dfd, path, LOOKUP_EMPTY, ...)`).
    let lf = vfs::LookupFlags {
        empty: (args.a2 & AT_EMPTY_PATH) != 0,
        no_follow_final: (args.a2 & AT_SYMLINK_NOFOLLOW) != 0,
        ..Default::default()
    };
    let vp = match crate::pathresolve::resolve_at_lookup(dirfd, args.a1, lf) {
        Ok(p) => p, Err(rv) => return rv,
    };
    if propagation != 0 {
        let kind = if propagation & MS_UNBINDABLE != 0 { Propagation::Unbindable }
            else if propagation & MS_SLAVE != 0 { Propagation::Slave }
            else if propagation & MS_SHARED != 0 { Propagation::Shared }
            else if propagation & MS_PRIVATE != 0 { Propagation::Private }
            else { Propagation::Private };
        // set_propagation keys on the MOUNTPOINT dentry; derive it from the mount
        // the walk crossed into (root mounts have none → propagation is a no-op).
        if let Some((mp, _)) = vfs::mount::mountpoint_of(vp.mnt_id) {
            let _ = vfs::mount::set_propagation(&mp, kind);
        }
    }
    // [D52] Apply the MNT_* option change to the mount the walk CROSSED INTO
    // (Linux `do_mount_setattr` keys on `path->mnt`); AT_RECURSIVE ⇒ subtree.
    if set_mnt != 0 || clr_mnt != 0 {
        let r = if (args.a2 & AT_RECURSIVE) != 0 {
            vfs::mount::mnt_setattr_tree_by_id(vp.mnt_id, set_mnt, clr_mnt)
        } else {
            vfs::mount::mnt_setattr_by_id(vp.mnt_id, set_mnt, clr_mnt)
        };
        if let Err(e) = r { return crate::namei_common::errno_from_vfs(e); }
    }
    0
}
