// sys_io_uring_setup (NR_IO_URING_SETUP=425) per docs/53§0 —
// per-syscall-file module. The ring/SQE/CQE machinery, op
// constants, and dispatch stay in the io_uring module; this file
// holds only the syscall handler.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use crate::io_uring::{
    make_io_uring_inode, IoUringInode, MAX_ENTRIES, OFF_CQ_HDR, OFF_CQ_RING, OFF_SQ_HDR, OFF_SQ_RING,
};

/// `sys_io_uring_setup(entries, *params)` — slot 425.
/// # C: O(1)
pub fn sys_io_uring_setup(args: &syscall::SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use vfs::{Dentry, File, OpenFlags};
    use syscall::errno::Errno;
    let entries = args.a0 as u32;
    let params  = args.a1;
    if entries == 0 || entries > MAX_ENTRIES {
        return -(Errno::Einval.as_i32() as i64);
    }
    let inode = match IoUringInode::new(entries) {
        Some(i) => i, None => return -(Errno::Enomem.as_i32() as i64),
    };
    if params != 0 && params < hal::USER_VA_END {
        let n = inode.ring.lock().entries;
        // SAFETY: params validated < USER_VA_END; struct io_uring_params is 120 bytes; CPL=0 writes through caller's AS.
        unsafe {
            for i in 0..120usize {
                core::ptr::write_volatile((params + i as u64) as *mut u8, 0);
            }
            core::ptr::write_volatile((params       ) as *mut u32, n);
            core::ptr::write_volatile((params +   4 ) as *mut u32, n);
            // sq_off at +40
            core::ptr::write_volatile((params + 40 +  0) as *mut u32, OFF_SQ_HDR    );
            core::ptr::write_volatile((params + 40 +  4) as *mut u32, OFF_SQ_HDR + 4);
            core::ptr::write_volatile((params + 40 +  8) as *mut u32, OFF_SQ_HDR + 8);
            core::ptr::write_volatile((params + 40 + 12) as *mut u32, OFF_SQ_HDR +12);
            core::ptr::write_volatile((params + 40 + 24) as *mut u32, OFF_SQ_RING);
            // cq_off at +72
            core::ptr::write_volatile((params + 72 +  0) as *mut u32, OFF_CQ_HDR    );
            core::ptr::write_volatile((params + 72 +  4) as *mut u32, OFF_CQ_HDR + 4);
            core::ptr::write_volatile((params + 72 +  8) as *mut u32, OFF_CQ_HDR + 8);
            core::ptr::write_volatile((params + 72 + 12) as *mut u32, OFF_CQ_HDR +12);
            core::ptr::write_volatile((params + 72 + 20) as *mut u32, OFF_CQ_RING);
        }
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode_ref: vfs::InodeRef = make_io_uring_inode(inode);
    let dentry = Dentry::new(None, "[io_uring]".to_string(), inode_ref.clone());
    let file = File::new(inode_ref, dentry, OpenFlags::O_RDWR);
    match fdt.alloc(file) { Ok(fd) => fd as i64, Err(e) => -(e as i64) }
}
