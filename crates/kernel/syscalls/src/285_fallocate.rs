// 285 fallocate — one syscall, one file (docs/53 §0). ABI shim only: the fd
// lookup (EBADF FIRST — `ksys_fallocate`, `fs/open.c:355-363`) and the call.
// The whole check ladder is `fs::fallocate::vfs_fallocate` (Linux
// `fs/open.c:250-352`).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_fallocate(fd, mode, offset, len)` — slot 285.
///
/// The fd lookup PRECEDES every argument check, so `fallocate(-1, 0, -1, -1)`
/// is EBADF and not EINVAL — the reverse of the pre-fix ordering.
/// # C: backend-dependent
pub fn sys_fallocate(args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU; Arc clone.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(args.a0 as i32) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    ::fs::fallocate::vfs_fallocate(cur, &file, args.a1 as u32, args.a2 as i64, args.a3 as i64)
}
