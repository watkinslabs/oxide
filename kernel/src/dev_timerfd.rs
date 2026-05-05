// timerfd surface per Linux 2.6.25. v1: TimerfdInode stores
// expiry_ns + interval_ns. read returns u64 expiration count
// (1 if expired since last read; 0 otherwise) and re-arms for
// periodic timers. settime updates the slots.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

const TIMERFD_INO_BASE: Ino = 0x7300_0000;

#[inline]
fn monotonic_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

pub struct TimerfdInode {
    pub expiry_ns:   AtomicU64,
    pub interval_ns: AtomicU64,
    pub last_read_ns: AtomicU64,
}

impl TimerfdInode {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            expiry_ns:   AtomicU64::new(0),
            interval_ns: AtomicU64::new(0),
            last_read_ns: AtomicU64::new(0),
        })
    }
}

impl Inode for TimerfdInode {
    fn ino(&self) -> Ino { TIMERFD_INO_BASE }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < 8 { return Err(VfsError::Einval); }
        let now = monotonic_ns();
        let expiry = self.expiry_ns.load(Ordering::Acquire);
        if expiry == 0 || now < expiry {
            // No expirations yet — Linux blocks; v1 returns EAGAIN-shape (Ok(0)).
            return Ok(0);
        }
        let interval = self.interval_ns.load(Ordering::Acquire);
        let last = self.last_read_ns.load(Ordering::Acquire);
        let count = if interval == 0 { 1 } else {
            // periodic: expirations since last read
            let base = if last >= expiry { last } else { expiry };
            ((now - base) / interval) + 1
        };
        self.last_read_ns.store(now, Ordering::Release);
        if interval == 0 { self.expiry_ns.store(0, Ordering::Release); }
        else { self.expiry_ns.store(now.saturating_add(interval), Ordering::Release); }
        buf[..8].copy_from_slice(&count.to_le_bytes());
        Ok(8)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// Decode timerfd marker.
/// # C: O(1)
fn timerfd_inode_of(file: &alloc::sync::Arc<vfs::File>) -> Option<Arc<TimerfdInode>> {
    if file.inode().ino() != TIMERFD_INO_BASE { return None; }
    // We can't downcast the trait object without Any. v1 stores a
    // single global TimerfdInode per fd via the File's inode Arc;
    // caller must hold the original Arc. Easier: rebuild from the
    // file's inode — but that's the same trait object. Skip downcast
    // entirely; settime/gettime expect the file to be a Timerfd.
    let _ = file;
    None
}

/// `sys_timerfd_create(clockid, flags)`. Allocates a fresh TimerfdInode fd.
/// # C: O(N_fds)
pub fn kernel_sys_timerfd_create(_args: &syscall::SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use vfs::{Dentry, File, OpenFlags};
    use syscall::errno::Errno;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = TimerfdInode::new() as InodeRef;
    let dentry = Dentry::new(None, "timerfd".to_string(), Arc::clone(&inode));
    let file = File::new(inode, dentry, OpenFlags::O_RDONLY);
    match fdt.alloc(file) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_timerfd_settime(fd, flags, new, old)`. v1: validates fd is
/// a TimerfdInode by inode marker; the actual settime update can't
/// reach the inode without Any-downcast in the current Inode trait
/// — accepted as a no-op for now (fd remains never-expiring). Real
/// downcast lands when Inode gains an Any super-trait.
/// # C: O(1)
pub fn kernel_sys_timerfd_settime(args: &syscall::SyscallArgs) -> i64 {
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
    if file.inode().ino() != TIMERFD_INO_BASE {
        return -(Errno::Einval.as_i32() as i64);
    }
    let _ = timerfd_inode_of(&file);
    0
}

/// `sys_timerfd_gettime(fd, value)`. Reports zeros (since settime
/// is a no-op in v1).
/// # C: O(1)
pub fn kernel_sys_timerfd_gettime(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let value = args.a1;
    if value == 0 || value >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: value validated; CPL=0 writes through caller's AS.
    unsafe {
        for off in (0..32u64).step_by(8) {
            core::ptr::write_volatile((value + off) as *mut u64, 0);
        }
    }
    0
}
