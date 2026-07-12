// 293 pipe2 — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::userbuf::validate_user_buf_writable;

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
    if flags & O_NOTIFICATION_PIPE != 0 { return -(Errno::Enopkg.as_i32() as i64); }
    if let Err(rv) = validate_user_buf_writable(pipefd, 8, 4) { return rv; }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let inode = ::fs::pipe::make_pipe_inode();
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
    let dentry = vfs::dcache::d_alloc_pseudo("pipe", inode.clone(), &crate::anon_dname::PIPE_OPS);
    let mut r_oflags = OpenFlags::O_RDONLY;
    let mut w_oflags = OpenFlags::O_WRONLY;
    if (flags & O_NONBLOCK) != 0 { r_oflags |= OpenFlags::O_NONBLOCK; w_oflags |= OpenFlags::O_NONBLOCK; }
    if (flags & O_DIRECT) != 0 { w_oflags |= OpenFlags::O_DIRECT; }
    let r_file = File::new(inode.clone(), dentry.clone(), r_oflags);
    let w_file = File::new(inode, dentry, w_oflags);
    let r_fd = match fdt.alloc_limit(r_file, cur.nofile_soft())  { Ok(f) => f, Err(e) => return -(e as i64) };
    let w_fd = match fdt.alloc_limit(w_file, cur.nofile_soft())  { Ok(f) => f, Err(e) => {
        let _ = fdt.close(r_fd);
        return -(e as i64);
    }};
    if (flags & O_CLOEXEC) != 0 {
        let _ = fdt.set_cloexec(r_fd, true);
        let _ = fdt.set_cloexec(w_fd, true);
    }
    // SAFETY: pipefd validated writable for the full int[2] output array.
    unsafe {
        core::ptr::write_volatile(pipefd as *mut i32,         r_fd);
        core::ptr::write_volatile((pipefd + 4) as *mut i32,   w_fd);
    }
    0
}
