// 003 close — one syscall, one file (docs/53 §0).

use syscall::{errno::Errno, SyscallArgs};

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// `sys_close(fd)` — slot 3. Drops the fd-table entry (vfs::FdTable::close).
/// # C: O(1)
pub fn sys_close(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match current_task() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; no concurrent fd_table writer.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let rv = match fdt.close(fd) {
        Ok(())  => 0,
        Err(e)  => -(e as i64),
    };
    #[cfg(all(target_os = "oxide-kernel", feature = "debug-fdlife"))]
    crate::fd_life::op(cur, &fdt, b"close", fd, -1, rv);
    rv
}
