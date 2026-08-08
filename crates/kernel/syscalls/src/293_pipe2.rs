// 293 pipe2 — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(any(target_os = "oxide-kernel", test))]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::userbuf::write_i32_pair;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// # C: O(1)
pub fn sys_pipe2(args: &SyscallArgs) -> i64 {
    use vfs::{File, OpenFlags};
    let pipefd = args.a0;
    let flags  = args.a1 as u32;
    const O_NONBLOCK: u32 = OpenFlags::O_NONBLOCK.bits();
    const O_DIRECT:   u32 = OpenFlags::O_DIRECT.bits();
    const O_CLOEXEC:  u32 = OpenFlags::O_CLOEXEC.bits();
    const O_NOTIFICATION_PIPE: u32 = OpenFlags::O_EXCL.bits();
    const VALID_FLAGS: u32 = O_CLOEXEC | O_NONBLOCK | O_DIRECT | O_NOTIFICATION_PIPE;
    if flags & !VALID_FLAGS != 0 { return -(Errno::Einval.as_i32() as i64); }
    let notification = flags & O_NOTIFICATION_PIPE != 0;
    let cur = match current_task() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let inode = match ::fs::pipe::make_pipe_inode() {
        Ok(i) => i,
        Err(e) => return -(e as i64),
    };
    let pd = ::fs::pipe::pipe_data(&inode).expect("pipe inode has PipeData");
    pd.writers.store(1, core::sync::atomic::Ordering::Release);
    pd.readers.store(1, core::sync::atomic::Ordering::Release);
    debug_ssh! {
        let w = pd.writers.load(core::sync::atomic::Ordering::Acquire);
        let r = pd.readers.load(core::sync::atomic::Ordering::Acquire);
        klog::write_raw(b"[INFO]  ssh-trace: pipe_create ino=");
        klog::write_dec_u64(pd.ino);
        klog::write_raw(b" tid=");
        klog::write_dec_u64(cur.tid as u64);
        klog::write_raw(b" w_post_store=");
        klog::write_dec_u64(w as u64);
        klog::write_raw(b" r_post_store=");
        klog::write_dec_u64(r as u64);
        klog::write_raw(b"\n");
    }
    // A notification pipe carries kernel-generated RECORDS rather than bytes:
    // the queue behind it is what its reads come from, and userspace may not
    // write into it at all.
    if notification { ::fs::watch_queue::attach(&inode); }
    let dentry = vfs::dcache::d_alloc_pseudo("pipe", inode.clone(), &crate::anon_dname::PIPE_OPS);
    let mut r_oflags = OpenFlags::O_RDONLY;
    let mut w_oflags = OpenFlags::O_WRONLY;
    if (flags & O_NONBLOCK) != 0 { r_oflags |= OpenFlags::O_NONBLOCK; w_oflags |= OpenFlags::O_NONBLOCK; }
    if (flags & O_DIRECT) != 0 { w_oflags |= OpenFlags::O_DIRECT; }
    let r_file = File::new(inode.clone(), dentry.clone(), r_oflags);
    let w_file = File::new(inode, dentry, w_oflags);
    let reserve_flags = OpenFlags::from_bits_retain(flags & O_CLOEXEC);
    let r_fd = match fdt.get_unused_fd_flags(reserve_flags, cur.nofile_soft()) {
        Ok(fd) => fd,
        Err(e) => return -(e as i64),
    };
    let w_fd = match fdt.get_unused_fd_flags(reserve_flags, cur.nofile_soft()) {
        Ok(fd) => fd,
        Err(e) => {
            fdt.put_unused_fd(r_fd);
            return -(e as i64);
        }
    };
    if let Err(rv) = write_i32_pair(pipefd, r_fd, w_fd) {
        fdt.put_unused_fd(r_fd);
        fdt.put_unused_fd(w_fd);
        return rv;
    }
    fdt.fd_install(r_fd, r_file);
    fdt.fd_install(w_fd, w_file);
    0
}
