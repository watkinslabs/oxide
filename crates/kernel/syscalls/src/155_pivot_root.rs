// 155 pivot_root — one syscall, one file (docs/53 §0). Moved verbatim from mount.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::mount_common::read_user_path_required;

/// `sys_pivot_root(new_root, put_old)` — slot 155. Makes the mount at
/// `new_root` the namespace root and relocates the old root tree under
/// `put_old` (`docs/16§6`). Requires CAP_SYS_ADMIN. Paths are resolved like
/// normal Linux pathnames, so relative arguments are interpreted against cwd.
/// # C: O(N_mounts)
pub fn sys_pivot_root(args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !cur.has_cap(sched::cap::SYS_ADMIN) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    let new_root = match read_user_path_required(args.a0) { Ok(s) => s, Err(rv) => return rv };
    let put_old  = match read_user_path_required(args.a1) { Ok(s) => s, Err(rv) => return rv };
    let (nr_target, _nr_display) = match crate::pathresolve::resolve_mount_target_raw(&new_root) {
        Ok(x) => x,
        Err(_) => {
            #[cfg(feature = "debug-mount")]
            { klog::write_raw(b"[PIVOT-SYSCALL] new_root resolve failed raw="); klog::write_raw(new_root.as_bytes()); klog::write_raw(b"\n"); }
            return -(Errno::Einval.as_i32() as i64);
        }
    };
    let po_path = match crate::pathresolve::resolve_path_raw(&put_old, false) {
        Ok(p) => p,
        Err(_) => {
            #[cfg(feature = "debug-mount")]
            { klog::write_raw(b"[PIVOT-SYSCALL] put_old resolve failed raw="); klog::write_raw(put_old.as_bytes()); klog::write_raw(b"\n"); }
            return -(Errno::Einval.as_i32() as i64);
        }
    };
    let _po_display = vfs::mount::render_path_for_mount(po_path.mnt_id, &po_path.dentry);
    // TEMP (D24, debug-mnt): mount-creating syscall ENTRY trace.
    #[cfg(feature = "debug-mount")]
    {
        klog::write_raw(b"[MNTCREATE] syscall=pivot_root flags=0x0 recursive=false source=");
        klog::write_raw(_nr_display.as_bytes());
        klog::write_raw(b" target="); klog::write_raw(_po_display.as_bytes());
        klog::write_raw(b"\n");
    }
    // new_root MUST be a mount; resolve it to the MOUNTPOINT dentry (the dentry
    // the mount is grafted at) WITHOUT crossing into that mount. A plain resolve
    // crosses in and yields the mount's ROOT dentry — ambiguous for a bind
    // (shares the source root dentry) and unmatchable by `mount_exact_at` (keyed
    // by mountpoint dentry) → the "new_root not a mount root" EINVAL that broke
    // systemd service mount-namespacing (ProtectSystem= et al) and deadlocked
    // sysinit. put_old resolves normally (a dir inside new_root's mount).
    let nr_d = nr_target.mountpoint;
    let po_d = po_path.dentry;
    #[cfg(feature = "debug-mount")]
    { klog::write_raw(b"[PIVOT-SYSCALL] reached vfs::pivot_root nr="); klog::write_raw(_nr_display.as_bytes()); klog::write_raw(b" po="); klog::write_raw(_po_display.as_bytes()); klog::write_raw(b"\n"); }
    match vfs::mount::pivot_root(&nr_d, &po_d) {
        Ok(())                    => 0,
        Err(vfs::VfsError::Ebusy) => -(Errno::Ebusy.as_i32() as i64),
        Err(_)                    => -(Errno::Einval.as_i32() as i64),
    }
}
