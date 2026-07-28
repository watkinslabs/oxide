// 436 close_range — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_close_range(first, last, flags)` — slot 436. Closes the
/// inclusive fd range [first, last]. CLOSE_RANGE_CLOEXEC (bit 2)
/// marks fds cloexec instead of closing. CLOSE_RANGE_UNSHARE (bit 1)
/// first installs a private fd table when the table is shared.
/// # C: O(open fds)
pub fn sys_close_range(args: &SyscallArgs) -> i64 {
    let first = args.a0 as u32;
    let last  = args.a1 as u32;
    let flags = args.a2 as u32;
    const CLOSE_RANGE_UNSHARE:  u32 = 0x2;
    const CLOSE_RANGE_CLOEXEC:  u32 = 0x4;
    const CLOSE_RANGE_KNOWN: u32 = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;
    if first > last || (flags & !CLOSE_RANGE_KNOWN) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let owned = match unsafe { cur.fd_table_ref() } {
        Some(t) => t, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // Linux `atomic_read(&cur_fds->count) > 1`: unshare only when ANOTHER task
    // still owns the table. The count must be read from the task's OWN Arc —
    // taking a local clone first adds a reference, which made the predicate
    // permanently true and unshared on every call. That is not merely wasteful:
    // installing a private table drops the old one, and `FdTable::drop` runs
    // `filp_close` for every descriptor in it, releasing the process's POSIX
    // record locks on files it still holds open. systemd issues
    // `close_range(..., CLOSE_RANGE_UNSHARE)` on every spawn.
    let shared = Arc::strong_count(owned) > 1;
    let fdt = owned.clone();
    let cloexec_only = (flags & CLOSE_RANGE_CLOEXEC) != 0;
    if (flags & CLOSE_RANGE_UNSHARE) != 0 && shared {
        let new_fdt = Arc::new(fdt.fork_clone_close_range(first, last, cloexec_only));
        // SAFETY: current task is the caller; replacing its fd table does not mutate other tasks still sharing the old Arc.
        unsafe { cur.replace_fd_table(Some(new_fdt)); }
        #[cfg(feature = "debug-fdlife")]
        crate::fd_life::op(cur, &fdt, b"close-range-unshare", first as i32, last as i32, flags as i64);
        return 0;
    }
    fdt.close_range(first, last, cloexec_only);
    #[cfg(feature = "debug-fdlife")]
    crate::fd_life::op(cur, &fdt, b"close-range", first as i32, last as i32, flags as i64);
    0
}
