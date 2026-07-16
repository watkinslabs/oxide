// 292 dup3 — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::OpenFlags;

/// `sys_dup3(oldfd, newfd, flags)` — slot 292. ABI shim.
/// Routes through `FdTable::dup3`, which enforces the Linux `ksys_dup3`
/// contract: flag bits other than O_CLOEXEC → EINVAL, oldfd==newfd → EINVAL,
/// and sets FD_CLOEXEC atomically with the install.
/// # C: O(1) + close
pub fn sys_dup3(args: &SyscallArgs) -> i64 {
    let oldfd = args.a0 as i32;
    let newfd = args.a1 as i32;
    // Reject unknown high bits before mapping: from_bits_truncate would drop
    // them, masking an invalid-flags EINVAL. Only O_CLOEXEC is valid for dup3.
    let flags = match OpenFlags::from_bits(args.a2 as u32) {
        Some(f) => f,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let rv = match fdt.dup3_limit(oldfd, newfd, flags, cur.nofile_soft()) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    };
    #[cfg(feature = "debug-fdlife")]
    crate::fd_life::op(cur, &fdt, b"dup3", oldfd, newfd, rv);
    rv
}
