// pidfd surface per Linux 5.3+. v1: each pidfd_open allocates a
// PidfdInode with the target tid encoded in the low 24 bits of the
// inode number; pidfd_send_signal extracts the tid by inode marker.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// Inode-number marker — high byte 0x70.
const PIDFD_INO_MARKER: Ino = 0x7000_0000;
const PIDFD_TID_MASK:   Ino = 0x00FF_FFFF;

/// Pidfd inode. Stores the target tid; read/write are noops (pidfds
/// aren't I/O fds — they're handles for pidfd_send_signal etc).
pub struct PidfdInode {
    pub tid: u32,
}

impl Inode for PidfdInode {
    fn ino(&self) -> Ino { PIDFD_INO_MARKER | (self.tid as Ino & PIDFD_TID_MASK) }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// Decode the tid from a pidfd inode-number; returns `None` for
/// non-pidfd inodes.
/// # C: O(1)
pub fn tid_from_ino(ino: Ino) -> Option<u32> {
    if (ino & 0xFF00_0000) == PIDFD_INO_MARKER {
        Some((ino & PIDFD_TID_MASK) as u32)
    } else { None }
}

/// Construct a pidfd inode for `tid`. Wraps in `Arc<dyn Inode>`.
/// # C: O(1)
pub fn new_pidfd_inode(tid: u32) -> InodeRef {
    Arc::new(PidfdInode { tid }) as InodeRef
}

/// `sys_pidfd_open(pid, flags)` — allocates a pidfd bound to `pid`.
/// # C: O(N_fds)
pub fn kernel_sys_pidfd_open(args: &syscall::SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use alloc::sync::Arc;
    use vfs::{Dentry, File, OpenFlags};
    use syscall::errno::Errno;
    let pid = args.a0 as u32;
    if crate::sched::registry::lookup(pid).is_none() {
        return -(Errno::Esrch.as_i32() as i64);
    }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = crate::dev_pidfd::new_pidfd_inode(pid);
    let dentry = Dentry::new(None, "pidfd".to_string(), Arc::clone(&inode));
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    match fdt.alloc(file) {
        Ok(fd)  => fd as i64,
        Err(e)  => -(e as i64),
    }
}

/// `sys_pidfd_send_signal(pidfd, sig, info, flags)` — slot 424.
/// Resolves the pidfd's bound tid via the inode marker and posts
/// the signal bit into that task's sigpending.
/// # C: O(N_tasks)
pub fn kernel_sys_pidfd_send_signal(args: &syscall::SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let fd  = args.a0 as i32;
    let sig = args.a1 as i32;
    if !(1..=64).contains(&sig) { return -(Errno::Einval.as_i32() as i64); }
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
    let tid = match crate::dev_pidfd::tid_from_ino(file.inode().ino()) {
        Some(t) => t, None => return -(Errno::Einval.as_i32() as i64),
    };
    let task = match crate::sched::registry::lookup(tid) {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    task.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
    0
}
