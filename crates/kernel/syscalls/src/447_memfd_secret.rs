// 447 memfd_secret — `SYSCALL_DEFINE1(memfd_secret)`.
// ABI shim (docs/53); the ladder is `crate::secretmem` (hosted-tested).
//
// Previously this slot did not exist: `route_b.rs` rewrote the arguments and
// called `sys_memfd_create(name = NULL, flags)`, which meant
// `memfd_secret(0)` returned EFAULT (memfd_create's NULL-name check) and
// `memfd_secret(O_CLOEXEC)` returned EINVAL (0x80000 is not an MFD_* bit) —
// and, had either succeeded, the caller would have received an ordinary
// shmem memfd whose pages stay in the kernel's linear map.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::SyscallArgs;
use vfs::{File, OpenFlags};

use crate::secretmem::memfd_secret_check;

#[inline]
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `memfd_secret(flags)` — slot 447. The descriptor is read-write and large-file
/// capable, and its name is its own: the file lives on its own pseudo
/// filesystem rather than among the shared anonymous inodes.
/// # C: O(N_fds) for the fd-table alloc
pub fn sys_memfd_secret(args: &SyscallArgs) -> i64 {
    // Linux declares `unsigned int flags`.
    let cloexec = match memfd_secret_check(args.a0 as u32) {
        Ok(c) => c,
        Err(e) => return err(e),
    };
    let cur = match sched::live::current() { Some(c) => c, None => return err(Errno::Ebadf) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return err(Errno::Ebadf),
    };
    let cred = crate::pathresolve::current_cred();
    let inode = ::fs::secretmem::secretmem_inode(cred.uid, cred.gid);
    let dentry = vfs::dcache::d_alloc_pseudo(::fs::secretmem::SECRETMEM_NAME, inode.clone(),
                                             &::fs::secretmem::SECRETMEM_OPS);
    let file = File::new(inode, dentry, OpenFlags::O_RDWR | OpenFlags::O_LARGEFILE);
    let fd = match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => fd, Err(e) => return -(e as i64),
    };
    if cloexec { let _ = fdt.set_cloexec(fd, true); }
    fd as i64
}
