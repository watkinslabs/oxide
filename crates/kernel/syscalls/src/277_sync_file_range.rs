// 277 sync_file_range — one syscall, one file (docs/53 §0). ABI shim only:
// the ladder and the range writeback are `fs::sync::sync_file_range`.
//
// The slot used to be folded into `sys_fsync`, which answered a different
// question entirely: it committed filesystem METADATA (Linux states outright
// that sync_file_range writes none), ignored `flags`,
// `offset` and `nbytes`, and therefore never produced EINVAL for a bad flag
// word or ESPIPE for a pipe.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_sync_file_range(fd, offset, nbytes, flags)` — slot 277.
/// The fd lookup is EBADF-first (Linux's `ksys_sync_file_range`);
/// every argument check happens after it, inside the work-fn.
/// # C: O(N_dirty in range)
pub fn sys_sync_file_range(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU; Arc clone.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    ::fs::sync::sync_file_range(&file, args.a1 as i64, args.a2 as i64, args.a3 as u32)
}
