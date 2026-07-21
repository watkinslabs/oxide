// 080 chdir — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_chdir(path)` — slot 80.
/// # C: O(N_devfs_entries)
pub fn sys_chdir(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let path = match crate::namei_common::read_user_path(path_ptr) {
        Ok(s)   => s,
        Err(rv) => return rv,
    };
    let raw: &str = path.as_str();
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    // chdir(2) follows symlinks to a directory — resolve via the
    // raw path-walk and require a directory. A resolved non-directory final
    // target is ENOTDIR (not ENOENT); other walk errors are preserved.
    let path_obj = match crate::pathresolve::resolve_path_raw(raw, false) {
        Ok(p) if matches!(p.inode.file_type(), vfs::FileType::Directory) => p,
        Ok(_p) => {
            #[cfg(feature = "debug-boot")]
            {
                klog::write_raw(b"[ENOTDIR] op=chdir why=target-not-dir tid=");
                klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
                klog::write_raw(b" raw=");
                klog::write_raw(raw.as_bytes());
                klog::write_raw(b"\n");
            }
            return -(Errno::Enotdir.as_i32() as i64);
        }
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    let rendered = vfs::mount::render_path_for_mount(path_obj.mnt_id, &path_obj.dentry);
    cur.set_fs_cwd(rendered, path_obj);
    0
}
