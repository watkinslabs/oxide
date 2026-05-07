// Anonymous-fd creators (eventfd2, memfd_create) extracted from
// syscall_glue_fs.rs to keep that file under the 1000-line cap.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{Dentry, File, OpenFlags};
use hal::USER_VA_END;

/// `sys_eventfd2(initval, flags)` — slot 290.
/// # C: O(1)
pub fn kernel_sys_eventfd2(args: &SyscallArgs) -> i64 {
    use alloc::string::ToString;
    let initval = args.a0;
    let _flags  = args.a1;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = crate::dev_pipe::EventfdInode::new(initval);
    let dentry = Dentry::new(None, "eventfd".to_string(), inode.clone());
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    match fdt.alloc(file) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_memfd_create(name, flags)` — slot 319.
/// # C: O(N_fds) for the fd-table alloc
pub fn kernel_sys_memfd_create(args: &SyscallArgs) -> i64 {
    const MFD_CLOEXEC:       u64 = 0x0001;
    const MFD_ALLOW_SEALING: u64 = 0x0002;
    const MFD_HUGETLB:       u64 = 0x0004;
    let name_ptr = args.a0;
    let flags    = args.a1;
    if (flags & MFD_HUGETLB) != 0 {
        return -(Errno::Enosys.as_i32() as i64);
    }
    let _ = MFD_ALLOW_SEALING;
    let name: String = if name_ptr == 0 || name_ptr >= USER_VA_END {
        String::from("memfd")
    } else {
        // SAFETY: name_ptr range validated; user page mapped under caller's AS; bounded read.
        let bytes = unsafe { crate::devfs::read_user_cstr(name_ptr, 256) };
        let s = bytes.and_then(|b| core::str::from_utf8(b).ok()).unwrap_or("memfd");
        let mut out = String::from("memfd:");
        out.push_str(s);
        out
    };
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = crate::tmpfs::TmpfsFileInode::new();
    let dentry = Dentry::new(None, name, inode.clone() as vfs::InodeRef);
    let file = File::new(inode as vfs::InodeRef, dentry, OpenFlags::O_RDWR);
    let fd = match fdt.alloc(file) {
        Ok(fd) => fd, Err(e) => return -(e as i64),
    };
    if (flags & MFD_CLOEXEC) != 0 {
        let _ = fdt.set_cloexec(fd, true);
    }
    fd as i64
}

/// `sys_mq_open(name, oflag, mode, attr)` — slot NR_MQ_OPEN. v1
/// returns a tmpfs-backed anonymous fd. mq_send/mq_receive
/// degrade to byte-FIFO write/read on this fd (no priority
/// ordering, no per-message boundaries — caller must size
/// records itself). Adequate for probe-and-survive paths;
/// programs that need real POSIX MQ semantics catch them in
/// P25f.
/// # C: O(N_fds)
pub fn kernel_sys_mq_open(args: &SyscallArgs) -> i64 {
    use alloc::string::ToString;
    let name_ptr = args.a0;
    let _oflag   = args.a1;
    let _mode    = args.a2;
    let _attr    = args.a3;
    let name: String = if name_ptr == 0 || name_ptr >= USER_VA_END {
        String::from("mq")
    } else {
        // SAFETY: name_ptr range validated; user page mapped under caller's AS; bounded read.
        let bytes = unsafe { crate::devfs::read_user_cstr(name_ptr, 256) };
        let s = bytes.and_then(|b| core::str::from_utf8(b).ok()).unwrap_or("mq");
        let mut out = String::from("mq:");
        out.push_str(s);
        out
    };
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = crate::tmpfs::TmpfsFileInode::new();
    let dentry = Dentry::new(None, name, inode.clone() as vfs::InodeRef);
    let file = File::new(inode as vfs::InodeRef, dentry, OpenFlags::O_RDWR);
    match fdt.alloc(file) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)`
/// — slot NR_MQ_TIMEDSEND. v1 ignores priority + timeout and routes
/// to write(fd, msg_ptr, msg_len). Returns 0 on success per POSIX
/// (NOT bytes written — that's write semantics). EAGAIN/EINVAL
/// surface from the underlying tmpfs write.
/// # C: O(msg_len)
pub fn kernel_sys_mq_timedsend(args: &SyscallArgs) -> i64 {
    let sa = SyscallArgs {
        a0: args.a0, a1: args.a1, a2: args.a2,
        a3: 0, a4: 0, a5: 0,
    };
    let r = crate::syscall_glue::kernel_sys_write(&sa);
    if r < 0 { r } else { 0 }
}

/// `sys_mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio_p, abs_timeout)`
/// — slot NR_MQ_TIMEDRECEIVE. v1 ignores priority output + timeout
/// and routes to read(fd, msg_ptr, msg_len). Returns the byte count
/// actually read (POSIX: bytes received in this message).
/// # C: O(msg_len)
pub fn kernel_sys_mq_timedreceive(args: &SyscallArgs) -> i64 {
    let sa = SyscallArgs {
        a0: args.a0, a1: args.a1, a2: args.a2,
        a3: 0, a4: 0, a5: 0,
    };
    crate::syscall_glue::kernel_sys_read(&sa)
}
