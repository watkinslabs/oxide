//! `signalfd(2)` / `signalfd4(2)` entry points and their error ordering.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use vfs::{File, OpenFlags};

use crate::userbuf::validate_user_buf;
use super::file::{SignalfdData, make_signalfd_inode};
use super::uapi::{SFD_CLOEXEC, SFD_NONBLOCK, SIGSET_BYTES};

/// `sys_signalfd(ufd, mask, sizemask)` — the 3-argument form always runs with
/// `flags = 0`; it has no flags argument to read.
/// # C: O(N_fds) for a new fd, O(1) for an update
pub fn sys_signalfd(args: &syscall::SyscallArgs) -> i64 {
    signalfd_common(args, 0)
}

/// `sys_signalfd4(ufd, mask, sizemask, flags)`. # C: as `sys_signalfd`
pub fn sys_signalfd4(args: &syscall::SyscallArgs) -> i64 {
    signalfd_common(args, args.a3)
}

/// Shared body. Error ordering, in Linux's sequence:
///   1. `sizemask != sizeof(sigset_t)` → EINVAL.
///   2. mask copy-in → EFAULT.
///   3. unknown flag bit → EINVAL.
///   4. `ufd >= 0`: bad fd → EBADF, non-signalfd → EINVAL.
/// # C: O(N_fds) for a new fd, O(1) for an update
fn signalfd_common(args: &syscall::SyscallArgs, flags: u64) -> i64 {
    let error = |errno: Errno| -(errno.as_i32() as i64);
    let in_fd     = args.a0 as i32;
    let mask_ptr  = args.a1;
    let mask_size = args.a2;
    if mask_size != SIGSET_BYTES { return error(Errno::Einval); }
    if let Err(rv) = validate_user_buf(mask_ptr, SIGSET_BYTES, 1) { return rv; }
    if flags & !(SFD_NONBLOCK | SFD_CLOEXEC) != 0 { return error(Errno::Einval); }
    // SAFETY: mask_ptr validated readable for one sigset_t word.
    let requested = unsafe { core::ptr::read_unaligned(mask_ptr as *const u64) };
    // SIGKILL/SIGSTOP are dropped from the accepted set SILENTLY, never
    // rejected: a signalfd that swallowed them would make the task unkillable.
    let mask = requested & !(sched::signum::Signum::Sigkill.bit()
                           | sched::signum::Signum::Sigstop.bit());
    #[cfg(feature = "debug-ssh")]
    {
        klog::write_raw(b"[INFO]  ssh-trace: signalfd4 in_fd=");
        klog::write_dec_u64(in_fd as u64);
        klog::write_raw(b" mask=");
        klog::write_hex_u64(mask);
        klog::write_raw(b"\n");
    }
    let cur = match sched::current() { Some(c) => c, None => return error(Errno::Ebadf) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return error(Errno::Ebadf),
    };
    if in_fd >= 0 {
        // Re-arm an existing signalfd with the new mask. `flags` is validated
        // above but otherwise ignored on this path — Linux applies
        // CLOEXEC/NONBLOCK only when it creates the description.
        let file = match fdt.get(in_fd) { Ok(f) => f, Err(_) => return error(Errno::Ebadf) };
        let Some(d) = file.inode().private::<SignalfdData>() else { return error(Errno::Einval) };
        d.mask.store(mask, Ordering::Release);
        // A widened mask can make an already-pending signal readable, so wake
        // every poll consumer of this thread's pending set.
        cur.sigpending.poll_subscribers().notify_mask(vfs::POLL_IN);
        return in_fd as i64;
    }
    let inode = make_signalfd_inode(mask);
    let dentry = vfs::dcache::d_alloc_pseudo("[signalfd]", Arc::clone(&inode),
        &crate::anon_dname::ANON_INODE_OPS);
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
