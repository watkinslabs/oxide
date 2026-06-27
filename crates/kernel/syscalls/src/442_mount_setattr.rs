// 442 mount_setattr — one syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.
#![cfg(target_os = "oxide-kernel")]

use alloc::string::ToString;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::fsmount_common::*;

/// `sys_mount_setattr(dirfd, path, flags, uattr, size)` — slot 442.
/// Changes mount attributes on the subtree at `path`: we honour the
/// propagation change (`mount_attr.propagation` → MS_SHARED/PRIVATE/SLAVE/
/// UNBINDABLE) via `vfs::mount::set_propagation`; RDONLY/NOSUID/… attr bits
/// are accepted (no per-mount flag store yet). ID-mapped mounts are not
/// implemented, so requests using `MOUNT_ATTR_IDMAP` are rejected instead of
/// falsely advertising support to systemd. `struct mount_attr` is
/// `{ u64 attr_set, attr_clr, propagation, userns_fd }` (32 bytes).
/// # C: O(N_mounts)
pub fn sys_mount_setattr(args: &SyscallArgs) -> i64 {
    use vfs::mount::Propagation;
    const MS_UNBINDABLE: u64 = 1 << 17;
    const MS_PRIVATE:    u64 = 1 << 18;
    const MS_SLAVE:      u64 = 1 << 19;
    const MS_SHARED:     u64 = 1 << 20;
    const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
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
    // SAFETY: uattr+16 is covered by the validated minimum struct size.
    let attr_set = unsafe { core::ptr::read_volatile(uattr as *const u64) };
    if (attr_set & MOUNT_ATTR_IDMAP) != 0 {
        return -(Errno::Einval.as_i32() as i64);
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
        let _ = vfs::mount::set_propagation(&abs, kind);
    }
    0
}
