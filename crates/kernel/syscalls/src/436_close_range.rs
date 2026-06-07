// 436 close_range — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_close_range(first, last, flags)` — slot 436. Closes the
/// inclusive fd range [first, last]. CLOSE_RANGE_CLOEXEC (bit 2)
/// marks fds cloexec instead of closing. CLOSE_RANGE_UNSHARE (bit 1)
/// is accepted as a no-op (single-process v1 has nothing to unshare).
/// # C: O(last - first)
pub fn sys_close_range(args: &SyscallArgs) -> i64 {
    let first = args.a0 as i32;
    let last  = args.a1 as i32;
    let flags = args.a2 as u32;
    const CLOSE_RANGE_CLOEXEC:  u32 = 0x4;
    if first < 0 || last < 0 || first > last {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let cloexec_only = (flags & CLOSE_RANGE_CLOEXEC) != 0;
    for fd in fdt.live_fds() {
        if fd < first || fd > last { continue; }
        if cloexec_only {
            let _ = fdt.set_cloexec(fd, true);
        } else {
            let _ = fdt.close(fd);
        }
    }
    0
}
