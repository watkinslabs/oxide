// signalfd surface per Linux 2.6.22. Each signalfd_create allocates a
// SignalfdInode storing the mask; signalfd(fd>=0,…) re-arms an existing fd
// with a new mask. read pops the lowest pending masked signal off
// current.sigpending and emits a 128-byte `signalfd_siginfo` record filled
// from the signal's queued siginfo: ssi_signo always, plus ssi_code/pid/uid
// and either ssi_status (SIGCHLD) or ssi_int/ssi_ptr (RT sigqueue value).





use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use vfs::{File, FileType, Ino, Inode, InodeRef, KResult, PollSubscribers, VfsError};
use vfs::{FileOps, InodeBuilder, default_inode_ops, mk_mode};
use crate::userbuf::validate_user_buf;

mod ids {
    use vfs::Ino;
    pub(crate) const INO_BASE: Ino = 0x7200_0000;
}
/// Linux `signalfd_siginfo` size — 128 bytes per `signalfd(2)`.
pub const SIGINFO_SIZE: usize = 128;

// `struct signalfd_siginfo` field byte offsets (Linux `linux/signalfd.h`).
const SSI_SIGNO:  usize = 0;   // u32 signal number
const SSI_CODE:   usize = 8;   // s32 si_code (SI_USER / CLD_* / SI_QUEUE …)
const SSI_PID:    usize = 12;  // u32 sender / child pid
const SSI_UID:    usize = 16;  // u32 sender / child real uid
const SSI_STATUS: usize = 40;  // s32 SIGCHLD exit status (wait-encoded)
const SSI_INT:    usize = 44;  // s32 sigqueue value.sival_int
const SSI_PTR:    usize = 48;  // u64 sigqueue value.sival_ptr
/// SIGCHLD signal number (its queued siginfo carries pid/uid/status/code).
const SIG_SIGCHLD: u32 = sched::signum::Signum::Sigchld as u32;

/// Per-inode signalfd state (Linux `i_private`): the signal mask read drains.
pub struct SignalfdData {
    pub mask: AtomicU64,
}

/// Test/helper factory. The signal wait source is selected dynamically when a
/// poll consumer registers the file. # C: O(1)
pub fn make_signalfd_inode(mask: u64) -> InodeRef {
    InodeBuilder::new(ids::INO_BASE, mk_mode(FileType::CharDev, 0),
        default_inode_ops(), Arc::new(SignalfdFileOps))
        .private(Arc::new(SignalfdData { mask: AtomicU64::new(mask) }))
        .build()
}

/// `i_fop` for a signalfd inode. # C: O(1)
struct SignalfdFileOps;
impl FileOps for SignalfdFileOps {
    fn read(&self, inode: &Inode, _o: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < SIGINFO_SIZE { return Err(VfsError::Einval); }
        let d = match inode.private::<SignalfdData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        let mask = d.mask.load(Ordering::Acquire);
        let cur = match sched::current() { Some(c) => c, None => return Ok(0) };
        let mut total = 0;
        while total + SIGINFO_SIZE <= buf.len() {
            match read_one_signal(&cur, mask, &mut buf[total..total + SIGINFO_SIZE]) {
                Ok(()) => total += SIGINFO_SIZE,
                Err(VfsError::Eagain) if total != 0 => break,
                Err(e) => return Err(e),
            }
        }
        Ok(total)
    }
    /// POLLIN only when a signal in this fd's mask is pending for the
    /// current task. The default Inode::poll (always-ready) made epoll
    /// spin: systemd's sd-event registers a signalfd, so an always-ready
    /// poll busy-looped epoll_pwait forever and PID1 never ran services.
    /// # C: O(1)
    fn poll(&self, inode: &Inode) -> u32 {
        let mask = match inode.private::<SignalfdData>() { Some(d) => d.mask.load(Ordering::Acquire), None => return 0 };
        let cur = sched::current();
        let deliver = cur.as_ref().map_or(0, |c| c.sigpending.load(Ordering::Acquire)) & mask;
        if deliver != 0 { vfs::POLL_IN } else { 0 }
    }
    fn poll_subscribers(&self, _file: &File) -> Option<Arc<PollSubscribers>> {
        sched::current().map(|c| c.sigpending.poll_subscribers())
    }
}

fn read_one_signal(cur: &sched::Task, mask: u64, out: &mut [u8]) -> KResult<()> {
        let pending = cur.sigpending.load(Ordering::Acquire);
        let deliver = pending & mask;
        // Empty signalfd: Linux returns EAGAIN (nonblocking) rather than a
        // 0-byte read. systemd's event loop logs "Truncated read from signal
        // fd (0 bytes)" on a 0 return and can busy-spin re-reading; EAGAIN is
        // the correct "nothing to read" answer. v1 signalfds are effectively
        // nonblocking (read never parks), so EAGAIN is always right here.
        if deliver == 0 { return Err(VfsError::Eagain); }
        let sig = (deliver.trailing_zeros() + 1) as u32;
        // Pop the signal + its queued siginfo through the one owner of that
        // decision (`Task::dequeue_siginfo`), so signalfd, rt_sigtimedwait and
        // handler delivery can never disagree about which queue backs a signal
        // or when its pending bit clears. RT signals keep the bit set while
        // records remain; SIGCHLD does the same over its child-event queue
        // (systemd reads pid/status/code here); standard signals clear on take.
        let (popped, empty) = cur.dequeue_siginfo(sig);
        if empty { cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release); }
        // Fill the 128-byte signalfd_siginfo: ssi_signo always; the queued
        // record supplies ssi_code/pid/uid and either ssi_status (SIGCHLD) or
        // ssi_int/ssi_ptr (an RT sigqueue value).
        for b in &mut out[..SIGINFO_SIZE] { *b = 0; }
        out[SSI_SIGNO..SSI_SIGNO + 4].copy_from_slice(&sig.to_le_bytes());
        if let Some(rec) = popped {
            out[SSI_CODE..SSI_CODE + 4].copy_from_slice(&rec.code.to_le_bytes());
            out[SSI_PID..SSI_PID + 4].copy_from_slice(&rec.pid.to_le_bytes());
            out[SSI_UID..SSI_UID + 4].copy_from_slice(&rec.uid.to_le_bytes());
            if sig == SIG_SIGCHLD {
                out[SSI_STATUS..SSI_STATUS + 4].copy_from_slice(&(rec.value as i32).to_le_bytes());
            } else {
                out[SSI_INT..SSI_INT + 4].copy_from_slice(&(rec.value as u32).to_le_bytes());
                out[SSI_PTR..SSI_PTR + 8].copy_from_slice(&rec.value.to_le_bytes());
            }
        }
        Ok(())
}

/// `sys_signalfd(fd, mask, mask_size)` / `sys_signalfd4(fd, mask, sz, flags)`.
/// fd == -1 → allocate new fd; fd >= 0 → update existing inode's mask.
/// # C: O(N_fds) for new; O(1) update
pub fn sys_signalfd(args: &syscall::SyscallArgs) -> i64 {
    sys_signalfd_common(args, 0)
}

pub fn sys_signalfd4(args: &syscall::SyscallArgs) -> i64 {
    sys_signalfd_common(args, args.a3)
}

fn sys_signalfd_common(args: &syscall::SyscallArgs, flags: u64) -> i64 {
    use vfs::{File, OpenFlags};
    use syscall::errno::Errno;
    let in_fd     = args.a0 as i32;
    let mask_ptr  = args.a1;
    let mask_size = args.a2;
    if mask_size != 8 { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_user_buf(mask_ptr, 8, 1) { return rv; }
    const SFD_NONBLOCK: u64 = 0o0_004_000;
    const SFD_CLOEXEC:  u64 = 0o2_000_000;
    if flags & !(SFD_NONBLOCK | SFD_CLOEXEC) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: mask_ptr validated readable for one sigset_t word.
    let mask = unsafe { core::ptr::read_unaligned(mask_ptr as *const u64) }
        & !(sched::signum::Signum::Sigkill.bit()
          | sched::signum::Signum::Sigstop.bit());
    #[cfg(feature = "debug-ssh")]
    {
        klog::write_raw(b"[INFO]  ssh-trace: signalfd4 in_fd=");
        klog::write_dec_u64(in_fd as u64);
        klog::write_raw(b" mask=");
        klog::write_hex_u64(mask);
        klog::write_raw(b"\n");
    }
    let cur = match sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if in_fd >= 0 {
        // Update the existing signalfd's mask in place (Linux `signalfd(fd,…)`
        // re-arms the fd with the new mask). EINVAL if `fd` is not a signalfd.
        let file = match fdt.get(in_fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
        match file.inode().private::<SignalfdData>() {
            Some(d) => { d.mask.store(mask, Ordering::Release); return in_fd as i64; }
            None => return -(Errno::Einval.as_i32() as i64),
        }
    }
    let inode = make_signalfd_inode(mask);
    let dentry = vfs::dcache::d_alloc_pseudo("[signalfd]", Arc::clone(&inode), &crate::anon_dname::ANON_INODE_OPS);
    let mut fl = OpenFlags::O_RDWR;
    if (flags & SFD_NONBLOCK) != 0 { fl |= OpenFlags::O_NONBLOCK; }
    let file = File::new(inode, dentry, fl);
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => {
            if (flags & SFD_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}
