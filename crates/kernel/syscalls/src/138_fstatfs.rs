// 138 fstatfs — one syscall, one file (docs/53 §0). Moved verbatim from statfs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::validate_user_buf;
use crate::statfs_common::{magic_for_path, usage_for, write_statfs, M_TMPFS};

/// `sys_fstatfs(fd, buf)` — slot 138. Reports the backing fs magic for
/// an open fd, classified by the path the fd was opened with.
/// # C: O(N_mounts)
pub fn sys_fstatfs(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    if let Err(rv) = validate_user_buf(buf, 120, 8) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    // open(2) stores the full open path as the (flat) dentry name.
    let name = file.dentry().name();
    let magic = if name.starts_with('/') { magic_for_path(name) } else { M_TMPFS };
    let (blocks, bfree, files) = usage_for(magic);
    write_statfs(buf, magic, blocks, bfree, files);
    0
}
