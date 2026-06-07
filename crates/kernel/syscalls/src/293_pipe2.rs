// 293 pipe2 — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

/// # C: O(1)
pub fn sys_pipe2(args: &SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use vfs::{Dentry, File, OpenFlags};
    let pipefd = args.a0;
    let flags  = args.a1 as u32;
    const O_NONBLOCK: u32 = 0o4000;
    const O_CLOEXEC:  u32 = 0o2000000;
    if pipefd == 0 || pipefd >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let inode = ::fs::pipe::PipeInode::new();
    inode.writers.store(1, core::sync::atomic::Ordering::Release);
    inode.readers.store(1, core::sync::atomic::Ordering::Release);
    debug_ssh! {
        let w = inode.writers.load(core::sync::atomic::Ordering::Acquire);
        let r = inode.readers.load(core::sync::atomic::Ordering::Acquire);
        klog::write_raw(b"[INFO]  ssh-trace: pipe_create ino=");
        klog::write_dec_u64(inode.ino);
        klog::write_raw(b" tid=");
        klog::write_dec_u64(cur.tid as u64);
        klog::write_raw(b" w_post_store=");
        klog::write_dec_u64(w as u64);
        klog::write_raw(b" r_post_store=");
        klog::write_dec_u64(r as u64);
        klog::write_raw(b"\n");
    }
    let dentry = Dentry::new(None, "pipe".to_string(), inode.clone());
    let mut r_oflags = OpenFlags::O_RDONLY;
    let mut w_oflags = OpenFlags::O_WRONLY;
    if (flags & O_NONBLOCK) != 0 { r_oflags |= OpenFlags::O_NONBLOCK; w_oflags |= OpenFlags::O_NONBLOCK; }
    let r_file = File::new(inode.clone(), dentry.clone(), r_oflags);
    let w_file = File::new(inode, dentry, w_oflags);
    let r_fd = match fdt.alloc(r_file)  { Ok(f) => f, Err(e) => return -(e as i64) };
    let w_fd = match fdt.alloc(w_file)  { Ok(f) => f, Err(e) => {
        let _ = fdt.close(r_fd);
        return -(e as i64);
    }};
    if (flags & O_CLOEXEC) != 0 {
        let _ = fdt.set_cloexec(r_fd, true);
        let _ = fdt.set_cloexec(w_fd, true);
    }
    // SAFETY: pipefd validated < USER_VA_END; user page mapped per active CR3 = caller's AS.
    unsafe {
        core::ptr::write_volatile(pipefd as *mut i32,         r_fd);
        core::ptr::write_volatile((pipefd + 4) as *mut i32,   w_fd);
    }
    0
}
