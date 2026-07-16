// 033 dup2 — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

use syscall::SyscallArgs;
use syscall::errno::Errno;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// `sys_dup2(oldfd, newfd)` — slot 33. ABI shim per `docs/53§4`.
/// Work fn: `vfs::FdTable::dup2`. oldfd==newfd returns newfd unchanged.
/// # C: O(1) + close
pub fn sys_dup2(args: &SyscallArgs) -> i64 {
    let oldfd = args.a0 as i32;
    let newfd = args.a1 as i32;
    let cur = match current_task() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let rv = match fdt.dup2_limit(oldfd, newfd, cur.nofile_soft()) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    };
    #[cfg(all(target_os = "oxide-kernel", feature = "debug-fdlife"))]
    crate::fd_life::op(cur, &fdt, b"dup2", oldfd, newfd, rv);
    rv
}
