// Completion-eventfd registration.

use syscall::errno::Errno;

use crate::io_uring::ctx::IoUringInode;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `IORING_REGISTER_EVENTFD` / `..._ASYNC`: `arg` is one `__s32` descriptor.
/// # C: O(1)
pub fn register(inode: &IoUringInode, arg: u64, async_only: bool) -> i64 {
    let mut b = [0u8; 4];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let raw = i32::from_ne_bytes(b);
    let Some(cur) = sched::live::current() else { return err(Errno::Ebadf) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return err(Errno::Ebadf) };
    let file = match fdt.clone().get(raw) { Ok(f) => f, Err(_) => return err(Errno::Ebadf) };
    let mut g = inode.reg.lock();
    if g.eventfd.is_some() { return err(Errno::Ebusy); }
    g.eventfd = Some(file);
    g.eventfd_async = async_only;
    0
}

/// `IORING_UNREGISTER_EVENTFD`. # C: O(1)
pub fn unregister(inode: &IoUringInode) -> i64 {
    let mut g = inode.reg.lock();
    if g.eventfd.take().is_none() { return err(Errno::Enxio); }
    g.eventfd_async = false;
    0
}
