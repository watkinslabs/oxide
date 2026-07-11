// 319 memfd_create — one syscall, one file (docs/53 §0). Moved verbatim from anonfd.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::vec::Vec;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{File, OpenFlags};

const MFD_CLOEXEC:       u64 = 0x0001;
const MFD_ALLOW_SEALING: u64 = 0x0002;
const MFD_HUGETLB:       u64 = 0x0004;
const MFD_NOEXEC_SEAL:   u64 = 0x0008;
const MFD_EXEC:          u64 = 0x0010;
const MFD_NAME_PREFIX: &[u8] = b"memfd:";
const MFD_NAME_MAX_LEN: usize = vfs::path::NAME_MAX - MFD_NAME_PREFIX.len();

#[inline]
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn read_memfd_name(name_ptr: u64) -> Result<String, i64> {
    if name_ptr == 0 { return Err(err(Errno::Efault)); }
    let raw = match syscall::scan_user_cstr(name_ptr, (MFD_NAME_MAX_LEN + 1) as u64, |va| {
        // SAFETY: scan_user_cstr bounds each user VA before asking for this byte.
        unsafe { core::ptr::read_volatile(va as *const u8) }
    }) {
        Ok(b) => b,
        Err(Errno::Enametoolong) => return Err(err(Errno::Einval)),
        Err(e) => return Err(err(e)),
    };
    let mut name = Vec::with_capacity(MFD_NAME_PREFIX.len() + raw.len());
    name.extend_from_slice(MFD_NAME_PREFIX);
    name.extend_from_slice(&raw);
    Ok(vfs::path_from_bytes(&name))
}

/// `sys_memfd_create(name, flags)` — slot 319.
/// # C: O(N_fds) for the fd-table alloc
pub fn sys_memfd_create(args: &SyscallArgs) -> i64 {
    let name_ptr = args.a0;
    let flags    = args.a1;
    let known = MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_NOEXEC_SEAL | MFD_EXEC;
    if flags & !known != 0 { return err(Errno::Einval); }
    if (flags & MFD_EXEC) != 0 && (flags & MFD_NOEXEC_SEAL) != 0 { return err(Errno::Einval); }
    if (flags & MFD_HUGETLB) != 0 { return err(Errno::Enosys); }
    let allow_sealing = (flags & (MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL)) != 0;
    let name = match read_memfd_name(name_ptr) {
        Ok(name) => name,
        Err(e) => return e,
    };
    let cur = match sched::live::current() {
        Some(c) => c, None => return err(Errno::Ebadf),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return err(Errno::Ebadf),
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
