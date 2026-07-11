// 319 memfd_create — one syscall, one file (docs/53 §0). Moved verbatim from anonfd.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{File, OpenFlags};

/// `sys_memfd_create(name, flags)` — slot 319.
/// # C: O(N_fds) for the fd-table alloc
pub fn sys_memfd_create(args: &SyscallArgs) -> i64 {
    const MFD_CLOEXEC:       u64 = 0x0001;
    const MFD_ALLOW_SEALING: u64 = 0x0002;
    const MFD_HUGETLB:       u64 = 0x0004;
    const MFD_NOEXEC_SEAL:   u64 = 0x0008;
    const MFD_EXEC:          u64 = 0x0010;
    let name_ptr = args.a0;
    let flags    = args.a1;
    let known = MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_NOEXEC_SEAL | MFD_EXEC;
    if flags & !known != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    if (flags & MFD_HUGETLB) != 0 {
        return -(Errno::Enosys.as_i32() as i64);
    }
    let allow_sealing = (flags & MFD_ALLOW_SEALING) != 0;
    let s = match crate::mount_common::read_user_cstr_owned(name_ptr, 256) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut name = String::from("memfd:");
    name.push_str(&s);
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = if allow_sealing {
        ::fs::tmpfs::tmpfs_sealable_file()
    } else {
        ::fs::tmpfs::tmpfs_anon_file()
    };
    let dentry = vfs::dcache::d_alloc_pseudo(&name, inode.clone(), &crate::anon_dname::MEMFD_OPS);
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    let fd = match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => fd, Err(e) => return -(e as i64),
    };
    if (flags & MFD_CLOEXEC) != 0 {
        let _ = fdt.set_cloexec(fd, true);
    }
    fd as i64
}
