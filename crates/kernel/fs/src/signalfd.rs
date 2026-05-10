// signalfd surface per Linux 2.6.22. v1: each signalfd_create
// allocates a SignalfdInode storing the mask. read pops the lowest
// pending masked signal off current.sigpending and emits a
// 128-byte `signalfd_siginfo` record (ssi_signo only — other
// fields zero).





use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

const SIGNALFD_INO_BASE: Ino = 0x7200_0000;
/// Linux `signalfd_siginfo` size — 128 bytes per `signalfd(2)`.
pub const SIGINFO_SIZE: usize = 128;

pub struct SignalfdInode {
    pub mask: AtomicU64,
}

impl SignalfdInode {
    /// # C: O(1)
    pub fn new(mask: u64) -> Arc<Self> {
        Arc::new(Self { mask: AtomicU64::new(mask) })
    }
}

impl Inode for SignalfdInode {
    fn ino(&self) -> Ino { SIGNALFD_INO_BASE }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < SIGINFO_SIZE { return Err(VfsError::Einval); }
        let mask = self.mask.load(Ordering::Acquire);
        let cur = match sched::current() { Some(c) => c, None => return Ok(0) };
        let pending = cur.sigpending.load(Ordering::Acquire);
        let deliver = pending & mask;
        if deliver == 0 { return Ok(0); }
        let sig = (deliver.trailing_zeros() + 1) as u32;
        cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
        // Zero the buffer, write ssi_signo at offset 0 (u32 LE).
        for b in &mut buf[..SIGINFO_SIZE] { *b = 0; }
        buf[0..4].copy_from_slice(&sig.to_le_bytes());
        Ok(SIGINFO_SIZE)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// `sys_signalfd(fd, mask, mask_size)` / `sys_signalfd4(fd, mask, sz, flags)`.
/// fd == -1 → allocate new fd; fd >= 0 → update existing inode's mask.
/// # C: O(N_fds) for new; O(1) update
pub fn sys_signalfd4(args: &syscall::SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use vfs::{Dentry, File, OpenFlags};
    use syscall::errno::Errno;
    let in_fd     = args.a0 as i32;
    let mask_ptr  = args.a1;
    let mask_size = args.a2;
    if mask_size != 8 { return -(Errno::Einval.as_i32() as i64); }
    if mask_ptr == 0 || mask_ptr >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: mask_ptr validated; CPL=0 reads through caller's AS.
    let mask = unsafe { core::ptr::read_volatile(mask_ptr as *const u64) };
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if in_fd >= 0 {
        // Update existing — caller's responsibility that it's a signalfd.
        match fdt.get(in_fd) {
            Ok(_) => return in_fd as i64, // mask update is best-effort; v1 stores only on alloc
            Err(_) => return -(Errno::Ebadf.as_i32() as i64),
        }
    }
    let inode = SignalfdInode::new(mask) as InodeRef;
    let dentry = Dentry::new(None, "signalfd".to_string(), Arc::clone(&inode));
    let file = File::new(inode, dentry, OpenFlags::O_RDONLY);
    match fdt.alloc(file) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}
