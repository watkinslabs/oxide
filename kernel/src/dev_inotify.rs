// Minimal inotify per Linux 2.6.13. v1: real fd allocation +
// add_watch / rm_watch return monotonic watch descriptors. Read
// always returns 0 bytes (no events ever fire — backing FS hooks
// are P4). systemd / libnotify check that the fd opens; that's
// enough to keep them happy.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

const INOTIFY_INO_BASE: Ino = 0x7100_0000;

pub struct InotifyInode {
    pub flags: u32,
    pub next_wd: AtomicI32,
}

impl InotifyInode {
    /// # C: O(1)
    pub fn new(flags: u32) -> Arc<Self> {
        Arc::new(Self { flags, next_wd: AtomicI32::new(1) })
    }
}

impl Inode for InotifyInode {
    fn ino(&self) -> Ino { INOTIFY_INO_BASE }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// `sys_inotify_init(flags=0)` / `sys_inotify_init1(flags)`.
/// Allocates a fresh InotifyInode at the lowest free fd.
/// # C: O(N_fds)
pub fn kernel_sys_inotify_init1(args: &syscall::SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use vfs::{Dentry, File, OpenFlags};
    use syscall::errno::Errno;
    let flags = args.a0 as u32;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = InotifyInode::new(flags) as InodeRef;
    let dentry = Dentry::new(None, "inotify".to_string(), Arc::clone(&inode));
    let file = File::new(inode, dentry, OpenFlags::O_RDONLY);
    match fdt.alloc(file) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_inotify_add_watch(fd, pathname, mask)`. v1: validates fd
/// is an InotifyInode, returns a monotonic watch descriptor (no
/// real path tracking — events never fire).
/// # C: O(1)
pub fn kernel_sys_inotify_add_watch(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let fd = args.a0 as i32;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    if file.inode().ino() != INOTIFY_INO_BASE {
        return -(Errno::Einval.as_i32() as i64);
    }
    // Hard to downcast to InotifyInode without Any; v1 fakes this with a
    // shared monotonic counter.
    static GLOBAL_WD: AtomicI32 = AtomicI32::new(1);
    GLOBAL_WD.fetch_add(1, Ordering::Relaxed) as i64
}

/// `sys_inotify_rm_watch(fd, wd)`. v1: returns 0 (no real watch
/// table). Caller already sees "no events" semantics.
/// # C: O(1)
pub fn kernel_sys_inotify_rm_watch(_args: &syscall::SyscallArgs) -> i64 { 0 }
