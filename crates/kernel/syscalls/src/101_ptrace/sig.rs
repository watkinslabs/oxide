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
    let suspended = cur.ptrace_options.load(Ordering::Acquire) & uapi::O_SUSPEND_SECCOMP != 0;
    let opts = crate::s101_ptrace_decide::check_options_full(
        data, cur.has_cap(sched::cap::SYS_ADMIN), seccomp, suspended)?;
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
///
/// The record is rendered by the SAME writer an `SA_SIGINFO` handler's frame
/// and `rt_sigtimedwait`'s copy-out use, so the union arm is picked once. A
/// local `_kill`-only store here reported every fault stop as a kill and put
/// a pid where the debugger reads `si_addr`.
/// # C: O(1)
pub fn getsiginfo(target: &Task, data: u64) -> Result<(), Errno> {
    let snap = target.ptrace_siginfo.lock().clone().ok_or(Errno::Einval)?;
    if crate::userbuf::validate_user_buf_writable(data, SIGINFO_BYTES, 1).is_err() {
        return Err(Errno::Efault);
    }
    crate::signal_common::write_user_siginfo(data, snap.signo, Some(snap));
    Ok(())
}

/// PTRACE_SETSIGINFO — same EINVAL-when-not-signal-stopped rule.
///
/// Linux copies the whole `kernel_siginfo` union in, so a tracer CAN rewrite
/// the `si_addr` of the fault its tracee is about to take, or hand it a
/// `_sigsys` record; the arm is recovered from `(si_signo, si_code)` by the
/// one classifier.
/// # C: O(1)
pub fn setsiginfo(target: &Task, data: u64) -> Result<(), Errno> {
    if target.ptrace_siginfo.lock().is_none() { return Err(Errno::Einval); }
    if crate::userbuf::validate_user_buf(data, SIGINFO_BYTES, 1).is_err() {
        return Err(Errno::Efault);
    }
    // SAFETY: `data..data+128` validated readable in the caller's AS; only si_signo is read directly here, at offset 0, and the rest is decoded by the shared reader from the same proven range.
    let signo = unsafe { core::ptr::read_unaligned(data as *const i32) } as u32;
    *target.ptrace_siginfo.lock() = Some(crate::signal_common::read_user_siginfo(data, signo));
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
    // A SEIZE-mode interrupt is a PTRACE_EVENT_STOP: the wait status a tracer
    // reads must carry the event byte, not a bare SIGSTOP.
    target.stop_code.store(uapi::event_stop_code(uapi::EVENT_STOP) as u32, Ordering::Release);
    target.stop_pending.store(true, Ordering::Release);
    // Same synthesised-event record `ptrace_do_notify` builds, and it names the
    // TRACEE — the tracer's own pid in that field would be read as the
    // `si_addr` of any record whose si_code selects the `_sigfault` arm.
    let vtid = target.vtid.load(Ordering::Acquire);
    *target.ptrace_siginfo.lock() = Some(crate::s101_ptrace_event::notify_record(
        if vtid != 0 { vtid } else { target.tid },
        target.creds.ruid.load(Ordering::Acquire),
        uapi::event_stop_code(uapi::EVENT_STOP)));
    sched::live::send_sig_priv_group(target, sched::Signum::Sigstop as u32);
    Ok(())
}

/// PTRACE_LISTEN — SEIZE-only, and the tracee must be in a
/// PTRACE_EVENT_STOP group-stop; anything else is EIO.
///
/// The tracee stays stopped, but arms `JOBCTL_LISTENING | JOBCTL_TRAP_STOP` so
/// that an asynchronous event — a SIGCONT reaching the group, a group stop
/// starting — RE-TRAPS it and is reported, instead of resuming it into
/// userspace with the event never announced. Without the latch, LISTEN was
/// indistinguishable from doing nothing.
/// # C: O(1)
pub fn listen(target: &Arc<Task>) -> Result<(), Errno> {
    if !target.ptrace_seized.load(Ordering::Acquire) { return Err(Errno::Eio); }
    let in_event_stop = target.ptrace_siginfo.lock().as_ref()
        .map(|si| uapi::event_of_stop_code(si.code) == uapi::EVENT_STOP)
        .unwrap_or(false);
    if !in_event_stop { return Err(Errno::Eio); }
    target.cont_pending.store(false, Ordering::Release);
    let armed = sched::jobctl::listen(target.jobctl.load(Ordering::Acquire));
    target.jobctl.store(armed, Ordering::Release);
    // The window LISTEN exists to close: an event that landed between the
    // tracee entering this trap and this call already set `TRAP_NOTIFY`, and
    // no further event is coming to wake it. Trigger the re-trap now, or the
    // tracee sleeps forever holding a report the tracer will never see.
    if sched::jobctl::retrap_pending(armed) {
        sched::live::registry::wake_if_stopped(target, sched::jobctl::WakeKind::Cont);
    }
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
