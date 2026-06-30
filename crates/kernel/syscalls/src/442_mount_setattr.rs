// 442 mount_setattr — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use alloc::string::ToString;

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
    let path = match read_cstr(args.a1, 256) {
        Some(s) => s, None => return -(Errno::Efault.as_i32() as i64),
    };
    let abs = crate::pathresolve::resolve_cwd(&path);
    let abs = if abs.len() > 1 { abs.trim_end_matches('/').to_string() } else { abs };
    let uattr = args.a3;
    let size  = args.a4 as usize;
    if uattr == 0 || size < 24 || uattr >= USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    if uattr.checked_add(size as u64).map(|end| end > USER_VA_END).unwrap_or(true) {
        return -(Errno::Efault.as_i32() as i64);
    }
    const AT_RECURSIVE: u64 = 0x8000;
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
    if propagation != 0 {
        let kind = if propagation & MS_UNBINDABLE != 0 { Propagation::Unbindable }
            else if propagation & MS_SLAVE != 0 { Propagation::Slave }
            else if propagation & MS_SHARED != 0 { Propagation::Shared }
            else if propagation & MS_PRIVATE != 0 { Propagation::Private }
            else { Propagation::Private };
        if let Some(d) = crate::pathresolve::mount_dentry(&abs) {
            let _ = vfs::mount::set_propagation(&d, kind);
        }
    }
    // [D52] Apply the MNT_* option change to the mount the walk CROSSED INTO
    // (Linux `do_mount_setattr` keys on `path->mnt`, NOT a re-derived dentry —
    // a mounted-fs root maps to no mountpoint, and a pseudo `s_root` is shared).
    if set_mnt != 0 || clr_mnt != 0 {
        let vp = match crate::pathresolve::resolve_path(&abs, false) {
            Some(p) => p, None => return -(Errno::Einval.as_i32() as i64),
        };
        let r = if (args.a2 & AT_RECURSIVE) != 0 {
            vfs::mount::mnt_setattr_tree_by_id(vp.mnt_id, set_mnt, clr_mnt)
        } else {
            vfs::mount::mnt_setattr_by_id(vp.mnt_id, set_mnt, clr_mnt)
        };
        if let Err(e) = r { return crate::namei_common::errno_from_vfs(e); }
    }
    0
}
