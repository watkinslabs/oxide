// 074 fsync — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// fsync / fdatasync — resolve fd → inode → `i_mapping` and flush its dirty
/// page-cache frames to disk (D8). A backend whose data is already on disk
/// (no `i_mapping`, or a clean mapping) is a fast no-op. # C: O(N_dirty)
pub fn sys_fsync(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match sched::live::current() { Some(c) => c, None => return errno(Errno::Ebadf) };
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU; clone Arc.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return errno(Errno::Ebadf) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return errno(Errno::Ebadf) };
    // D8: flush the inode's page-cache (mmap-written frames reach disk here).
    if let Some(m) = file.inode().i_mapping() {
        if m.writeback().is_err() { return errno(Errno::Eio); }
    }
    0
}
