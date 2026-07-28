// 187 readahead — one syscall, one file (docs/53 §0). ABI shim only: the
// admission ladder and the cache fill are `fs::readahead::readahead`
// (Linux `mm/readahead.c` `ksys_readahead`).
//
// The slot previously fell through to the compat table's `sys_fadvise_validate`,
// which checked only that `fd` was open and returned 0 — accept-and-ignore.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_readahead(fd, offset, count)` — slot 187. EBADF for a closed fd comes
/// first (`mm/readahead.c:730-731`); everything else is decided by the work-fn.
/// # C: O(pages in range)
pub fn sys_readahead(args: &SyscallArgs) -> i64 {
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
    ::fs::readahead::readahead(&file, args.a1 as i64, args.a2)
}
