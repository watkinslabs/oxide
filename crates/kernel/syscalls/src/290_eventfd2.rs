// 290 eventfd2 — one syscall, one file (docs/53 §0). Moved verbatim from anonfd.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{File, OpenFlags};

/// `sys_eventfd2(initval, flags)` — slot 290.
/// # C: O(1)
pub fn sys_eventfd(args: &SyscallArgs) -> i64 {
    sys_eventfd_common(args, 0)
}

pub fn sys_eventfd2(args: &SyscallArgs) -> i64 {
    sys_eventfd_common(args, args.a1)
}

fn sys_eventfd_common(args: &SyscallArgs, flags: u64) -> i64 {
    const EFD_SEMAPHORE: u64 = 1;
    const EFD_NONBLOCK:  u64 = 0o0_004_000;
    const EFD_CLOEXEC:   u64 = 0o2_000_000;
    let initval = args.a0;
    if flags & !(EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = ::fs::pipe::make_eventfd_inode(initval, flags & EFD_SEMAPHORE != 0);
    let dentry = vfs::dcache::d_alloc_pseudo("[eventfd]", inode.clone(), &crate::anon_dname::ANON_INODE_OPS);
    let mut fl = OpenFlags::O_RDWR;
    if (flags & EFD_NONBLOCK) != 0 { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode, dentry, fl);
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => {
            if (flags & EFD_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}
