// PTRACE_SETOPTIONS / GETEVENTMSG / GETSIGINFO / SETSIGINFO /
// GETSIGMASK / SETSIGMASK / INTERRUPT / LISTEN.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use alloc::sync::Arc;
use sched::Task;
use syscall::errno::Errno;
use crate::s101_ptrace_uapi as uapi;

const SIGINFO_BYTES: u64 = 128;
const SIGSET_BYTES: u64 = 8;

/// PTRACE_SETOPTIONS. Unknown option bits are EINVAL (Linux
/// `check_ptrace_options`), unlike PTRACE_SEIZE's EIO for the same bits.
/// # C: O(1)
pub fn setoptions(cur: &Task, target: &Task, data: u64) -> Result<(), Errno> {
    let seccomp = security::seccomp::mode_of_current() != 0;
    let opts = crate::s101_ptrace_decide::check_options(data, cur.has_cap(sched::cap::SYS_ADMIN), seccomp)?;
    target.ptrace_options.store(opts, Ordering::Release);
    Ok(())
}

/// PTRACE_GETEVENTMSG — the message the last PTRACE_EVENT_* stop recorded.
/// # C: O(1)
pub fn geteventmsg(target: &Task, data: u64) -> Result<(), Errno> {
    put_u64(data, target.ptrace_eventmsg.load(Ordering::Acquire))
}

/// PTRACE_GETSIGINFO. Linux `ptrace_getsiginfo` returns **EINVAL** when the
/// tracee has no `last_siginfo` — i.e. it is not stopped for a signal. A
/// synthesised SIGTRAP record (what this used to return) tells a tracer a
/// signal arrived that never did.
/// # C: O(1)
pub fn getsiginfo(target: &Task, data: u64) -> Result<(), Errno> {
    let snap = target.ptrace_siginfo.lock().clone().ok_or(Errno::Einval)?;
    if crate::userbuf::validate_user_buf_writable(data, SIGINFO_BYTES, 1).is_err() {
        return Err(Errno::Efault);
    }
    // SAFETY: `data..data+128` validated as a mapped writable siginfo_t slot in the caller's AS; the leading fields follow the Linux `siginfo_t` layout (signo@0, errno@4, code@8, pid@16, uid@20, value@24) and the remainder is zeroed.
    unsafe {
        core::ptr::write_bytes(data as *mut u8, 0, SIGINFO_BYTES as usize);
        core::ptr::write_unaligned(data as *mut i32, snap.signo as i32);
        core::ptr::write_unaligned((data +  8) as *mut i32, snap.code);
        core::ptr::write_unaligned((data + 16) as *mut u32, snap.pid);
        core::ptr::write_unaligned((data + 20) as *mut u32, snap.uid);
        core::ptr::write_unaligned((data + 24) as *mut u64, snap.value);
    }
    Ok(())
}

/// PTRACE_SETSIGINFO — same EINVAL-when-not-signal-stopped rule.
/// # C: O(1)
pub fn setsiginfo(target: &Task, data: u64) -> Result<(), Errno> {
    if target.ptrace_siginfo.lock().is_none() { return Err(Errno::Einval); }
    if crate::userbuf::validate_user_buf(data, SIGINFO_BYTES, 1).is_err() {
        return Err(Errno::Efault);
    }
    // SAFETY: `data..data+128` validated readable in the caller's AS; fields read at the Linux `siginfo_t` offsets.
    let info = unsafe {
        sched::SigInfo {
            signo: core::ptr::read_unaligned(data as *const i32) as u32,
            code:  core::ptr::read_unaligned((data +  8) as *const i32),
            pid:   core::ptr::read_unaligned((data + 16) as *const u32),
            uid:   core::ptr::read_unaligned((data + 20) as *const u32),
            value: core::ptr::read_unaligned((data + 24) as *const u64),
        }
    };
    *target.ptrace_siginfo.lock() = Some(info);
    Ok(())
}

/// PTRACE_GETSIGMASK — `addr` must be `sizeof(sigset_t)`, else EINVAL.
/// # C: O(1)
pub fn getsigmask(target: &Task, addr: u64, data: u64) -> Result<(), Errno> {
    if addr != SIGSET_BYTES { return Err(Errno::Einval); }
    put_u64(data, target.sigmask.load(Ordering::Acquire))
}

/// PTRACE_SETSIGMASK. SIGKILL and SIGSTOP are stripped from the new mask
/// (Linux `sigdelsetmask`), so a tracer cannot make its tracee unkillable.
/// # C: O(1)
pub fn setsigmask(target: &Task, addr: u64, data: u64) -> Result<(), Errno> {
    if addr != SIGSET_BYTES { return Err(Errno::Einval); }
    if crate::userbuf::validate_user_buf(data, SIGSET_BYTES, 1).is_err() {
        return Err(Errno::Efault);
    }
    // SAFETY: `data..data+8` validated readable in the caller's AS; sigset_t is a bare u64 on both supported arches.
    let new = unsafe { core::ptr::read_unaligned(data as *const u64) };
    let undeniable = sched::Signum::Sigkill.bit() | sched::Signum::Sigstop.bit();
    target.sigmask.store(new & !undeniable, Ordering::Release);
    Ok(())
}

/// PTRACE_INTERRUPT — SEIZE-only (Linux tests `PT_SEIZED` and falls out with
/// the switch's initial `ret = -EIO` otherwise).
/// # C: O(1)
pub fn interrupt(target: &Arc<Task>) -> Result<(), Errno> {
    if !target.ptrace_seized.load(Ordering::Acquire) { return Err(Errno::Eio); }
    target.stop_signal.store(sched::Signum::Sigstop as u8, Ordering::Release);
    target.stop_pending.store(true, Ordering::Release);
    *target.ptrace_siginfo.lock() = Some(sched::SigInfo {
        signo: sched::Signum::Sigtrap as u32,
        code: ((uapi::EVENT_STOP << 8) | sched::Signum::Sigtrap as u32) as i32,
        pid: 0, uid: 0, value: 0,
    });
    target.sigpending.fetch_or(sched::Signum::Sigstop.bit(), Ordering::Release);
    sched::live::signal_wake_up(target);
    Ok(())
}

/// PTRACE_LISTEN — SEIZE-only, and the tracee must be in a
/// PTRACE_EVENT_STOP group-stop; anything else is EIO.
/// # C: O(1)
pub fn listen(target: &Task) -> Result<(), Errno> {
    if !target.ptrace_seized.load(Ordering::Acquire) { return Err(Errno::Eio); }
    let in_event_stop = target.ptrace_siginfo.lock().as_ref()
        .map(|si| ((si.code >> 8) as u32) == uapi::EVENT_STOP)
        .unwrap_or(false);
    if !in_event_stop { return Err(Errno::Eio); }
    target.cont_pending.store(false, Ordering::Release);
    Ok(())
}

fn put_u64(data: u64, v: u64) -> Result<(), Errno> {
    if crate::userbuf::validate_user_buf_writable(data, 8, 1).is_err() {
        return Err(Errno::Efault);
    }
    // SAFETY: `data..data+8` validated as a mapped writable range in the caller's AS; unaligned store, as Linux `put_user` permits.
    unsafe { core::ptr::write_unaligned(data as *mut u64, v); }
    Ok(())
}
