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
pub fn sys_eventfd2(args: &SyscallArgs) -> i64 {
    use alloc::string::ToString;
    const EFD_SEMAPHORE: u64 = 1;
    const EFD_NONBLOCK:  u64 = 0o0_004_000;
    const EFD_CLOEXEC:   u64 = 0o2_000_000;
    let initval = args.a0;
    let flags   = args.a1;
    let _ = EFD_SEMAPHORE; // semaphore mode honored at read-side TBD
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = ::fs::pipe::EventfdInode::new(initval);
    let dentry = Dentry::new(None, "eventfd".to_string(), inode.clone());
    let mut fl = OpenFlags::O_RDWR;
    if (flags & EFD_NONBLOCK) != 0 { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode, dentry, fl);
    match fdt.alloc(file) {
        Ok(fd) => {
            if (flags & EFD_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

/// `sys_memfd_create(name, flags)` — slot 319.
/// # C: O(N_fds) for the fd-table alloc
pub fn sys_memfd_create(args: &SyscallArgs) -> i64 {
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
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = ::fs::tmpfs::TmpfsFileInode::new();
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

