// `sys_chroot(path)` — slot 161 (F95). Per-task VFS root for absolute path
// walks. Inherited by fork; cleared only via explicit chroot. Requires
// CAP_SYS_CHROOT.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_chroot(path)` — slot 161.
/// # C: O(len)
pub fn sys_chroot(args: &SyscallArgs) -> i64 {
    let p = args.a0;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !cur.has_cap(sched::cap::SYS_CHROOT) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let path = match crate::namei_common::read_user_path(p) {
        Ok(s)   => s,
        Err(rv) => return rv,
    };
    let s: &str = path.as_str();
    // TEMP (D24, debug-mnt): mount-creating syscall ENTRY trace — chroot into the
    // assembled sandbox root that pins cur_mnt_id 10/11 for the api-mount walks.
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[MNTCREATE] syscall=chroot flags=0x0 recursive=false source=<none> target=");
        klog::write_raw(s.as_bytes());
        klog::write_raw(b"\n");
    }
    // chroot(2) accepts absolute and relative paths. Both must resolve through
    // the live `(root,cwd)` VFS identities; the stored string is display only.
    let root_obj = match crate::pathresolve::resolve_path_raw(s, false) {
        Ok(p) if matches!(p.inode.file_type(), vfs::FileType::Directory) => p,
        Ok(p)  => {
            trace_chroot_enotdir(s, s, p.mnt_id);
            return -(Errno::Enotdir.as_i32() as i64);
        }
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    let new_root = vfs::mount::render_path_for_mount(root_obj.mnt_id, &root_obj.dentry);
    cur.set_fs_root(new_root, root_obj);
    0
}

#[cfg(feature = "debug-boot")]
fn trace_chroot_enotdir(raw: &str, resolved: &str, mnt_id: u64) {
    klog::write_raw(b"[ENOTDIR] op=chroot why=target-not-dir tid=");
    klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
    klog::write_raw(b" raw=");
    klog::write_raw(raw.as_bytes());
    klog::write_raw(b" resolved=");
    klog::write_raw(resolved.as_bytes());
    klog::write_raw(b" mnt=");
    klog::write_dec_u64(mnt_id);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-boot"))]
fn trace_chroot_enotdir(_raw: &str, _resolved: &str, _mnt_id: u64) {}
