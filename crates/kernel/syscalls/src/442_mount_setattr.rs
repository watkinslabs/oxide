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
/// are accepted (no per-mount flag store yet). `struct mount_attr` is
/// `{ u64 attr_set, attr_clr, propagation, userns_fd }` (32 bytes).
/// # C: O(N_mounts)
pub fn sys_mount_setattr(args: &SyscallArgs) -> i64 {
    use vfs::mount::Propagation;
    const MS_UNBINDABLE: u64 = 1 << 17;
    const MS_PRIVATE:    u64 = 1 << 18;
    const MS_SLAVE:      u64 = 1 << 19;
    const MS_SHARED:     u64 = 1 << 20;
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
