// sys_wait4 — the shared wait(2)-family engine (`do_wait`) plus the wait4 ABI
// shim. Event-class selection, idtype mapping, and the wstatus/siginfo decode
// are pure and live in `syscall::wait`; this file only drives the registry and
// copies out. `waitid` enters through `wait_engine` with a different
// `WaitEvents`/`consume` pair rather than a second, divergent loop.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::rusage::Rusage;
use syscall::SyscallArgs;
use syscall::wait::{
    int_arg_from_reg, wait4_options_valid, wait4_upid_is_esrch, WaitEventKind, WaitEvents, WNOHANG,
};
use sched::registry::WaitChildSnapshot;

/// One wait(2)-family request as the engine sees it.
#[derive(Copy, Clone)]
pub(crate) struct WaitRequest {
    /// `wait4` pid form: -1 any, 0 caller's pgrp, >0 pid, <0 pgrp.
    pub pid:     i32,
    /// Raw option bits — the engine forwards them to child eligibility
    /// (`__WALL`/`__WCLONE`/`__WNOTHREAD`) and reads `WNOHANG`.
    pub options: u64,
    /// Which event classes may be reported.
    pub events:  WaitEvents,
    /// False = `WNOWAIT`: observe the event, leave it waitable.
    pub consume: bool,
}

/// `sys_wait4(pid, wstatus, options, rusage)`.
/// # C: O(N_loop × N_children)
pub fn sys_wait4(args: &SyscallArgs) -> i64 {
    let pid     = args.a0 as i32;
    let wstatus = args.a1;
    let options = int_arg_from_reg(args.a2);
    let rusage  = args.a3;

    if !wait4_options_valid(options) { return -(Errno::Einval.as_i32() as i64); }
    if wait4_upid_is_esrch(pid) { return -(Errno::Esrch.as_i32() as i64); }
    let req = WaitRequest { pid, options, events: WaitEvents::for_wait4(options), consume: true };
    wait_engine(req, |_kind, wstat| write_wstatus(wstatus, wstat), |child| write_rusage(rusage, child))
}

/// One pass over the waiter's eligible children. Exits are considered before
/// stops/continues, matching the per-task order `wait_consider_task` uses.
/// # C: O(N_children log N_tasks)
fn take_event(req: &WaitRequest, w: (u32, u32, u32)) -> Option<(WaitChildSnapshot, WaitEventKind, i32)> {
    let (tid, tgid, pgid) = w;
    if req.events.exited {
        let z = if req.consume { sched::live::reap_one(tid, tgid, req.pid, pgid, req.options) }
                else            { sched::live::peek_one(tid, tgid, req.pid, pgid, req.options) };
        if let Some((child, code)) = z {
            return Some((child, WaitEventKind::Exited, sched::exit::status::wait_status(code)));
        }
    }
    // Always scanned: a tracer sees its tracee's trap stop with no WUNTRACED
    // bit set. Reached only after the zombie lookup missed, so the common
    // wait4-for-an-exited-child path pays nothing extra.
    let (child, kind, sig) = sched::live::registry::child_stop_event(
        tid, tgid, req.pid, pgid, req.options, req.events.stopped, req.events.continued, req.consume)?;
    let wstat = match kind {
        WaitEventKind::Continued => sched::exit::status::continued_status(),
        _                        => sched::exit::status::stopped_status(sig as i32),
    };
    Some((child, kind, wstat))
}

/// Shared wait engine (`do_wait`). Syscall `wait4` passes user-copy sinks;
/// `waitid` passes kernel-local ones.
/// # C: O(N_loop × N_children)
pub(crate) fn wait_engine<F, R>(req: WaitRequest, mut write_status: F, mut write_usage: R) -> i64
where
    F: FnMut(WaitEventKind, i32) -> Result<(), i64>,
    R: FnMut(WaitChildSnapshot) -> Result<(), i64>,
{
    let w = match sched::live::current() {
        Some(c) => (c.tid, c.tgid.load(core::sync::atomic::Ordering::Acquire), c.pgid()),
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    loop {
        if let Some((child, kind, wstat)) = take_event(&req, w) {
            if let Err(rv) = write_status(kind, wstat) { return rv; }
            if let Err(rv) = write_usage(child) { return rv; }
            if kind == WaitEventKind::Exited && req.consume { drop_sigchld_if_drained(&req, w); }
            debug_sched! { klog::write_raw(b"[INFO]  sys_wait4: reaped\n"); }
            return child.vpid as i64;
        }
        if !sched::live::registry::has_wait_children(w.0, w.1, req.pid, w.2, req.options) {
            #[cfg(feature = "debug-boot")]
            {
                klog::write_raw(b"[wait4 ECHILD] parent="); klog::write_dec_u64(w.0 as u64);
                klog::write_raw(b" reqpid="); klog::write_hex_u64(req.pid as u32 as u64);
                if let Some(c) = sched::live::current() {
                    c.with_exe_path(|p| if let Some(p) = p {
                        klog::write_raw(b" exe="); klog::write_raw(p.as_bytes());
                    });
                }
                klog::write_raw(b"\n");
            }
            return -(Errno::Echild.as_i32() as i64);
        }
        if (req.options & WNOHANG) != 0 { return 0; }
        // Interruptible wait: `do_wait` runs at TASK_INTERRUPTIBLE. A
        // deliverable (unmasked) signal — and ALWAYS SIGKILL/SIGSTOP
        // regardless of mask, since signal(7) makes both unblockable —
        // aborts the blocking wait with -ERESTARTSYS. The syscall-return tail
        // (dispatch.rs `take_lowest_pending`) then runs the fatal-signal
        // default action (SIG_DFL terminate). Ordered AFTER the event scan
        // above (an available event is reported even with a signal pending)
        // and BEFORE park: without it a task parked here is unkillable —
        // kill() wakes it (wake_if_sleeping) but it just re-parks, never
        // returning to the dispatch tail that converts SIGKILL→terminate.
        if signal_aborts_wait() { return syscall::restart::restart_sys(); }
        // SAFETY: process ctx; runqueue installed; preempt-off; park+schedule per `13§8`.
        unsafe { sched::live::park_for_wait4(); }
        // F143: post-park recheck closes the missed-wakeup race where a child
        // exits between the scan above and `park_for_wait4` — firing
        // wake_wait4_parent while WAITERS is empty loses the wake.
        if let Some((child, kind, wstat)) = take_event(&req, w) {
            sched::live::unpark_self_from_wait4();
            if let Err(rv) = write_status(kind, wstat) { return rv; }
            if let Err(rv) = write_usage(child) { return rv; }
            if kind == WaitEventKind::Exited && req.consume { drop_sigchld_if_drained(&req, w); }
            return child.vpid as i64;
        }
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
    }
}

/// F237: once no waitable zombie remains for this parent, clear the pending
/// SIGCHLD bit. Left set, `signal_dispatch` fires a SIGCHLD handler AFTER
/// wait4 already reaped — the shell's handler then calls
/// `waitpid(-1, WNOHANG)`, gets -1/ECHILD, and corrupts `$?` to 255.
/// # C: O(N_zombies)
fn drop_sigchld_if_drained(req: &WaitRequest, w: (u32, u32, u32)) {
    if sched::live::has_wait_zombies(w.0, w.1, req.pid, w.2, req.options) { return; }
    if let Some(cur) = sched::live::current() {
        // The child record is queued on the PROCESS' shared set, so the private
        // bit alone is not the whole pending SIGCHLD — dropping only that left
        // the record and the shared bit behind for a later handler run.
        cur.flush_pending_signal_shared(sched::live::sigpend::Signum::Sigchld.as_u8() as usize);
    }
}

/// # C: O(1)
fn signal_aborts_wait() -> bool {
    use core::sync::atomic::Ordering;
    use sched::live::sigpend::Signum;
    let Some(cur) = sched::live::current() else { return false };
    let forced  = Signum::Sigkill.bit() | Signum::Sigstop.bit();
    let pending = cur.pending_signals();
    let masked  = cur.sigmask.load(Ordering::Acquire);
    ((pending & !masked) | (pending & forced)) != 0
}

/// Copy out the child's `struct rusage`. The wait-family reports `RUSAGE_BOTH`
/// — the child's own counters plus those it accumulated from its own reaped
/// children — which `WaitChildSnapshot::from_task` has already folded.
/// # C: O(1)
pub(crate) fn write_rusage(ptr: u64, child: WaitChildSnapshot) -> Result<(), i64> {
    write_rusage_bytes(ptr, child.rusage)
}

/// # C: O(1)
pub(crate) fn write_rusage_bytes(ptr: u64, r: Rusage) -> Result<(), i64> {
    if ptr == 0 { return Ok(()); }
    let bytes = r.encode();
    crate::userbuf::validate_user_buf_writable(ptr, bytes.len() as u64, 1)?;
    // SAFETY: full rusage byte range validated writable in the caller's AS; a byte copy needs no alignment, as Linux copy_to_user permits.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len()); }
    Ok(())
}

#[inline]
fn write_wstatus(ptr: u64, val: i32) -> Result<(), i64> {
    if ptr == 0 { return Ok(()); }
    crate::userbuf::validate_user_buf_writable(ptr, 4, 1)?;
    // SAFETY: exact writable user byte range validated; Linux copyout accepts unaligned int storage.
    unsafe { core::ptr::write_unaligned(ptr as *mut i32, val); }
    Ok(())
}
