// 081 fchdir — one syscall, one file (docs/53 §0). ABI shim only: the directory
// gate, MAY_EXEC check and pwd install are `fs::cwd::set_fs_pwd`.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_fchdir(fd)` — slot 81. Set the pwd to the opened directory's path.
/// # C: O(depth)
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
    let file = match fdt.get(fd) {
        Ok(f)  => f,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    // Linux uses `fd_raw` here: an O_PATH fd IS a valid fchdir target.
    ::fs::cwd::set_fs_pwd(vfs::VfsPath {
        mnt_id: file.mnt_id(),
        dentry: file.dentry().clone(),
        inode:  file.inode().clone(),
        last_component: None,
    }, &crate::pathresolve::current_cred())
}
