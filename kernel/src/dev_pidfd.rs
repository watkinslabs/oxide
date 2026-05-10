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
    // F109: pidfd_open with pid arg interpreted in caller's pid_ns.
    let cur_ns = crate::sched::current()
        .map(|c| c.pid_ns.load(core::sync::atomic::Ordering::Acquire))
        .unwrap_or(0);
    if crate::sched::registry::lookup_in_ns(cur_ns, pid).is_none() {
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
    if !crate::syscalls::signal::sig_perm_check(cur, &task, sig) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    task.sigpending.fetch_or(1u64 << (sig - 1), Ordering::Release);
    0
}

/// `sys_pidfd_getfd(pidfd, targetfd, flags)` — slot 438. Clones the
/// target task's fd into the calling task's fd table. Used by sandbox
/// programs (e.g. systemd-machined) that need to manipulate fds in
/// another process.
///
/// Linux semantics:
///   * `flags` must be 0 (any non-zero is EINVAL).
///   * pidfd must be a valid pidfd inode.
///   * Target task's targetfd must be open.
///   * Returns a new fd referring to the same Arc<File> (shared open
///     file description, so cursor + flock state are shared with the
///     target task — exactly what callers expect for fd-passing).
/// # C: O(N_fds)
pub fn kernel_sys_pidfd_getfd(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let pidfd     = args.a0 as i32;
    let target_fd = args.a1 as i32;
    let flags     = args.a2 as u32;
    if flags != 0 { return -(Errno::Einval.as_i32() as i64); }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot for cur.
    let cur_fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let pidfd_file = match cur_fdt.get(pidfd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let tid = match crate::dev_pidfd::tid_from_ino(pidfd_file.inode().ino()) {
        Some(t) => t, None => return -(Errno::Einval.as_i32() as i64),
    };
    let target = match crate::sched::registry::lookup(tid) {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: target task may be running on another CPU but fd_table
    // pointer is set once at spawn (or via replace_fd_table at execve);
    // Arc<FdTable> Acquire snapshot is safe under per-task UP invariant.
    let target_fdt = match unsafe { target.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let cloned = match target_fdt.get(target_fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    match cur_fdt.alloc(cloned) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}
