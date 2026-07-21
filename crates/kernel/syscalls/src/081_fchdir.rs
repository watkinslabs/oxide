// 081 fchdir — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_fchdir(fd)` — slot 81. Set cwd to the opened directory's path.
/// # C: O(1)
pub fn sys_fchdir(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    match fdt.get(fd) {
        Ok(file) => {
            if !matches!(file.inode().file_type(), vfs::FileType::Directory) {
                return -(Errno::Enotdir.as_i32() as i64);
            }
            let path = vfs::mount::render_path_for_mount(file.mnt_id(), file.dentry());
            let path_obj = vfs::VfsPath {
                mnt_id: file.mnt_id(),
                dentry: file.dentry().clone(),
                inode: file.inode().clone(),
                last_component: None,
            };
            cur.set_fs_cwd(path, path_obj);
            0
        }
        Err(_) => -(Errno::Ebadf.as_i32() as i64),
    }
}
