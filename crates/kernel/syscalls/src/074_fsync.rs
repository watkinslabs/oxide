// 074 fsync / 075 fdatasync — one file (docs/53 §0). ABI shim only: the flush
// itself is `fs::sync::vfs_fsync` (Linux `fs/sync.c` `do_fsync`).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// `do_fsync(fd, datasync)` (Linux `fs/sync.c`) — the body both slots share.
/// # C: O(N_dirty)
fn do_fsync(args: &SyscallArgs, datasync: bool) -> i64 {
    let fd = args.a0 as i32;
    let cur = match sched::live::current() { Some(c) => c, None => return errno(Errno::Ebadf) };
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU; clone Arc.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return errno(Errno::Ebadf) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return errno(Errno::Ebadf) };
    ::fs::sync::vfs_fsync(&file, datasync)
}

/// `sys_fsync(fd)` — slot 74. # C: O(N_dirty)
pub fn sys_fsync(args: &SyscallArgs) -> i64 { do_fsync(args, false) }

/// `sys_fdatasync(fd)` — slot 75: flush data plus only the metadata a reader
/// needs to reach it, skipping timestamp-only updates. # C: O(N_dirty)
pub fn sys_fdatasync(args: &SyscallArgs) -> i64 { do_fsync(args, true) }
