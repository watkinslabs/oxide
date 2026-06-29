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
            let bytes = file.dentry().absolute_path();
            let path = match core::str::from_utf8(&bytes) {
                Ok(s) if s.starts_with('/') => alloc::string::String::from(s),
                _ => return -(Errno::Enoent.as_i32() as i64),
            };
            let path_obj = match crate::pathresolve::resolve_path(&path, false) {
                Some(p) if matches!(p.inode.file_type(), vfs::FileType::Directory) => p,
                _ => return -(Errno::Enoent.as_i32() as i64),
            };
            // SAFETY: single-mutator per `13§5`; current task is sole writer.
            unsafe {
                *cur.cwd.get() = path;
                *cur.cwd_vfs.get() = Some(path_obj);
            }
            0
        }
        Err(_) => -(Errno::Ebadf.as_i32() as i64),
    }
}
