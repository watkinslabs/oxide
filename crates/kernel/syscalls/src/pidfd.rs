// pidfd surface per Linux 5.3+. v1: each pidfd_open allocates a
// PidfdInode with the target tid encoded in the low 24 bits of the
// inode number; pidfd_send_signal extracts the tid by inode marker.


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

/// `ioctl(pidfd, PIDFD_GET_INFO)` (Linux 6.13+). Returns a populated
/// `struct pidfd_info` for the target. systemd forks a service (e.g.
/// console-getty) then verifies it is its own child via this ioctl to
/// read `ppid`; an ENOTTY makes systemd conclude the child is foreign
/// and SIGKILL it — the getty never stays up and never re-prompts after
/// logout. `id` is the value the pidfd was opened with (a vpid in the
/// opener's pid_ns); resolve via tid then vpid.
///
/// Request encodes `_IOWR(0xFF, 11, struct pidfd_info)`; the struct size
/// (bits 16..=29) varies across kernel/systemd versions, so match on
/// dir|type|nr only and honor the caller's size for the write-back.
/// # C: O(N_tasks)
pub fn handle_pidfd_ioctl(id: u32, req: u64, arg: u64) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    // dir(IOWR=3)|type(0xFF)|nr(11) with the size field masked out.
    const PIDFD_GET_INFO_DTN: u64 = 0xC000_FF0B;
    const PIDFD_INFO_PID:   u64 = 1 << 0;
    const PIDFD_INFO_CREDS: u64 = 1 << 1;
    if (req & 0xC000_FFFF) != PIDFD_GET_INFO_DTN {
        return -(Errno::Enotty.as_i32() as i64);
    }
    let want = ((req >> 16) & 0x3FFF) as usize; // caller's sizeof(struct)
    if arg == 0 || arg >= hal::USER_VA_END || want < 64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let task = match sched::live::registry::lookup(id)
        .or_else(|| sched::live::registry::lookup_by_vpid(id))
    {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // SAFETY: arg validated in user range; 8-byte read of the requested mask.
    let req_mask = unsafe { core::ptr::read_volatile(arg as *const u64) };
    let pid  = sched::live::registry::display_vpid(task.tid) as u32;
    let ppid = sched::live::registry::parent_vpid(task.tid) as u32;
    // struct pidfd_info: mask@0 cgroupid@8 pid@16 tgid@20 ppid@24
    // ruid@28 rgid@32 euid@36 egid@40 suid@44 sgid@48 fsuid@52 fsgid@56 exit_code@60
    let mut out = [0u8; 64];
    let mut omask = PIDFD_INFO_PID; // pid/tgid/ppid always provided
    out[16..20].copy_from_slice(&pid.to_le_bytes());
    out[20..24].copy_from_slice(&pid.to_le_bytes());
    out[24..28].copy_from_slice(&ppid.to_le_bytes());
    if req_mask & PIDFD_INFO_CREDS != 0 {
        omask |= PIDFD_INFO_CREDS;
        let c = &task.creds;
        out[28..32].copy_from_slice(&c.ruid.load(Ordering::Acquire).to_le_bytes());
        out[32..36].copy_from_slice(&c.rgid.load(Ordering::Acquire).to_le_bytes());
        out[36..40].copy_from_slice(&c.euid.load(Ordering::Acquire).to_le_bytes());
        out[40..44].copy_from_slice(&c.egid.load(Ordering::Acquire).to_le_bytes());
        out[44..48].copy_from_slice(&c.suid.load(Ordering::Acquire).to_le_bytes());
        out[48..52].copy_from_slice(&c.sgid.load(Ordering::Acquire).to_le_bytes());
        out[52..56].copy_from_slice(&c.fsuid.load(Ordering::Acquire).to_le_bytes());
        out[56..60].copy_from_slice(&c.fsgid.load(Ordering::Acquire).to_le_bytes());
    }
    out[0..8].copy_from_slice(&omask.to_le_bytes());
    // SAFETY: arg..arg+64 inside the caller's >=64-byte buffer (want>=64);
    // CPL=0 byte writes through the caller's address space.
    unsafe { for i in 0..64 { core::ptr::write_volatile((arg + i as u64) as *mut u8, out[i]); } }
    0
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
pub fn sys_pidfd_open(args: &syscall::SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use alloc::sync::Arc;
    use vfs::{Dentry, File, OpenFlags};
    use syscall::errno::Errno;
    const PIDFD_NONBLOCK: u64 = 0o0_004_000;
    let pid = args.a0 as u32;
    let flags = args.a1;
    // F109: pidfd_open with pid arg interpreted in caller's pid_ns.
    let cur_ns = sched::live::current()
        .map(|c| c.pid_ns.load(core::sync::atomic::Ordering::Acquire))
        .unwrap_or(0);
    if sched::live::registry::lookup_in_ns(cur_ns, pid).is_none() {
        return -(Errno::Esrch.as_i32() as i64);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = crate::pidfd::new_pidfd_inode(pid);
    let dentry = Dentry::new(None, "pidfd".to_string(), Arc::clone(&inode));
    let mut fl = OpenFlags::O_RDWR;
    if (flags & PIDFD_NONBLOCK) != 0 { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode, dentry, fl);
    match fdt.alloc(file) {
        Ok(fd)  => fd as i64,
        Err(e)  => -(e as i64),
    }
}

/// `sys_pidfd_send_signal(pidfd, sig, info, flags)` — slot 424.
/// Resolves the pidfd's bound tid via the inode marker and posts
/// the signal bit into that task's sigpending.
/// # C: O(N_tasks)
pub fn sys_pidfd_send_signal(args: &syscall::SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let fd  = args.a0 as i32;
    let sig = args.a1 as i32;
    if !(1..=64).contains(&sig) { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let tid = match crate::pidfd::tid_from_ino(file.inode().ino()) {
        Some(t) => t, None => return -(Errno::Einval.as_i32() as i64),
    };
    let task = match sched::live::registry::lookup(tid) {
        Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !crate::signal::sig_perm_check(cur, &task, sig) {
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
pub fn sys_pidfd_getfd(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let pidfd     = args.a0 as i32;
    let target_fd = args.a1 as i32;
    let flags     = args.a2 as u32;
    if flags != 0 { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot for cur.
    let cur_fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let pidfd_file = match cur_fdt.get(pidfd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let tid = match crate::pidfd::tid_from_ino(pidfd_file.inode().ino()) {
        Some(t) => t, None => return -(Errno::Einval.as_i32() as i64),
    };
    let target = match sched::live::registry::lookup(tid) {
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
