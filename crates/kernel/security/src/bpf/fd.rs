// Descriptor publication for fd-backed BPF objects.

extern crate alloc;
use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::InodeRef;

/// Publish a BPF object on a descriptor that must not survive `execve`.
/// # C: O(fd words)
pub(crate) fn install_fd(inode: InodeRef, name: &str) -> Result<i64, Errno> {
    install_fd_access(inode, name, vfs::OpenFlags::O_RDWR)
}

/// Publish one descriptor with the requested access mode and close-on-exec.
/// # C: O(fd words)
pub(crate) fn install_fd_access(
    inode: InodeRef,
    name: &str,
    access: vfs::OpenFlags,
) -> Result<i64, Errno> {
    use vfs::{File, OpenFlags};
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off on the syscall path; sole reader of the fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let dentry = vfs::dcache::d_alloc_pseudo(
        name, Arc::clone(&inode), &crate::anon_dname::ANON_INODE_OPS,
    );
    let file = File::new(inode, dentry, access);
    // The descriptor allocator fails only with EMFILE (RLIMIT_NOFILE).
    fdt.install_limit(file, OpenFlags::O_CLOEXEC, cur.nofile_soft())
        .map(|fd| fd as i64)
        .map_err(|_| Errno::Emfile)
}
