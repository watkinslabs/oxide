// sys_wait4 — the shared wait(2)-family engine (`do_wait`) plus the wait4 ABI
// shim. Every decision this file used to make is now pure and lives in
// `syscall::wait`: the prologue's errno order (`wait::prepare`), the scan's
// class gating and event→status mapping (`wait::scan`), and the siginfo image
// `waitid` copies out (`wait::siginfo`). This file drives the registry, parks,
// and copies out. `waitid` enters through `wait_engine` with a different plan
// rather than a second, divergent loop.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::rusage::Rusage;
use syscall::SyscallArgs;
use syscall::wait::{
    drains_sigchld, scan_pass, wait4_prepare, wait_step, WaitEventKind, WaitPlan, WaitStep,
};
use sched::registry::WaitChildSnapshot;

/// `sys_wait4(pid, wstatus, options, rusage)`.
/// # C: O(N_loop × N_children)
pub fn sys_wait4(args: &SyscallArgs) -> i64 {
    let wstatus = args.a1;
    let rusage  = args.a3;
    let plan = match wait4_prepare(args.a0 as i32, args.a2) {
        Ok(p)  => p,
        Err(e) => return -(e.as_i32() as i64),
    };
    wait_engine(plan, |_kind, wstat| write_wstatus(wstatus, wstat), |child| write_rusage(rusage, child))
}

/// One pass over the waiter's eligible children. The ordering and the
/// per-class gating are `syscall::wait::scan_pass`'s; this supplies the two
/// registry lookups it drives.
/// # C: O(N_children log N_tasks)
fn take_event(plan: &WaitPlan, w: (u32, u32, u32)) -> Option<(WaitChildSnapshot, WaitEventKind, i32)> {
    let (tid, tgid, pgid) = w;
    scan_pass(plan,
        |consume| {
            let z = if consume { sched::live::reap_one(tid, tgid, plan.pid, pgid, plan.options) }
                    else       { sched::live::peek_one(tid, tgid, plan.pid, pgid, plan.options) };
            z.map(|(child, code)| (child, sched::exit::status::wait_status(code)))
        },
        |want_stop, want_cont, consume| {
            sched::live::registry::child_stop_event(
                tid, tgid, plan.pid, pgid, plan.options, want_stop, want_cont, consume)
                .map(|(child, kind, code)| (child, kind, code as i32))
        })
}

/// Shared wait engine (`do_wait`). Syscall `wait4` passes user-copy sinks;
/// `waitid` passes kernel-local ones.
/// # C: O(N_loop × N_children)
pub(crate) fn wait_engine<F, R>(plan: WaitPlan, mut write_status: F, mut write_usage: R) -> i64
where
    F: FnMut(WaitEventKind, i32) -> Result<(), i64>,
    R: FnMut(WaitChildSnapshot) -> Result<(), i64>,
{
    let w = match sched::live::current() {
        Some(c) => {
            let ns = sched::live::registry::reader_pid_ns();
            (c.tid, c.tgid.load(core::sync::atomic::Ordering::Acquire), c.pgrp().nr_in_or_tid(&ns))
        }
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    loop {
        let event = take_event(&plan, w);
        // Ordering owned by `syscall::wait::wait_step` (`do_wait`/`__do_wait`):
        // an available event outranks a pending signal; ECHILD outranks
        // WNOHANG; and the signal check is ordered BEFORE the park, or a task
        // parked here is unkillable — kill() wakes it (wake_if_sleeping) but
        // it just re-parks, never returning to the dispatch tail that turns
        // SIGKILL into the SIG_DFL terminate.
        let step = wait_step(
            event.is_some(),
            sched::live::registry::has_wait_children(w.0, w.1, plan.pid, w.2, plan.options),
            plan.options,
            signal_aborts_wait());
        match step {
            WaitStep::Report => {
                let (child, kind, wstat) = match event { Some(e) => e, None => continue };
                if let Err(rv) = report(&plan, w, child, kind, wstat, &mut write_status, &mut write_usage) { return rv; }
                debug_sched! { klog::write_raw(b"[INFO]  sys_wait4: reaped\n"); }
                return child.vpid as i64;
            }
            WaitStep::Echild => {
                #[cfg(feature = "debug-boot")]
                {
                    klog::write_raw(b"[wait4 ECHILD] parent="); klog::write_dec_u64(w.0 as u64);
                    klog::write_raw(b" reqpid="); klog::write_hex_u64(plan.pid as u32 as u64);
                    if let Some(c) = sched::live::current() {
                        c.with_exe_path(|p| if let Some(p) = p {
                            klog::write_raw(b" exe="); klog::write_raw(p.as_bytes());
                        });
                    }
                    klog::write_raw(b"\n");
                }
                return -(Errno::Echild.as_i32() as i64);
            }
            WaitStep::Nohang  => return 0,
            WaitStep::Restart => return syscall::restart::restart_sys(),
            WaitStep::Park    => {}
        }
        // SAFETY: process ctx; runqueue installed; preempt-off; park+schedule per `13§8`.
        unsafe { sched::live::park_for_wait4(); }
        // F143: post-park recheck closes the missed-wakeup race where a child
        // exits between the scan above and `park_for_wait4` — firing
        // wake_wait4_parent while WAITERS is empty loses the wake.
        if let Some((child, kind, wstat)) = take_event(&plan, w) {
            sched::live::unpark_self_from_wait4();
            if let Err(rv) = report(&plan, w, child, kind, wstat, &mut write_status, &mut write_usage) { return rv; }
            return child.vpid as i64;
        }
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
    }
}

/// Copy the event out and settle the parent's pending SIGCHLD.
/// # C: O(N_zombies)
fn report<F, R>(plan: &WaitPlan, w: (u32, u32, u32), child: WaitChildSnapshot,
                kind: WaitEventKind, wstat: i32, write_status: &mut F, write_usage: &mut R)
    -> Result<(), i64>
where
    F: FnMut(WaitEventKind, i32) -> Result<(), i64>,
    R: FnMut(WaitChildSnapshot) -> Result<(), i64>,
{
    write_status(kind, wstat)?;
    write_usage(child)?;
    if drains_sigchld(kind, plan.consume) { drop_sigchld_if_drained(plan, w); }
    Ok(())
}

/// F237: once no waitable zombie remains for this parent, clear the pending
/// SIGCHLD bit. Left set, `signal_dispatch` fires a SIGCHLD handler AFTER
/// wait4 already reaped — the shell's handler then calls
/// `waitpid(-1, WNOHANG)`, gets -1/ECHILD, and corrupts `$?` to 255.
/// # C: O(N_zombies)
fn drop_sigchld_if_drained(plan: &WaitPlan, w: (u32, u32, u32)) {
    if sched::live::has_wait_zombies(w.0, w.1, plan.pid, w.2, plan.options) { return; }
    if let Some(cur) = sched::live::current() {
        // The child record is queued on the PROCESS' shared set, so the private
        // bit alone is not the whole pending SIGCHLD — dropping only that left
        // the record and the shared bit behind for a later handler run.
        cur.flush_pending_signal_shared(sched::live::sigpend::Signum::Sigchld.as_u8() as usize);
    }
}

/// `do_wait` parks in `TASK_INTERRUPTIBLE`, so the abort condition is
/// `signal_pending_state(TASK_INTERRUPTIBLE, current)` — THE definition every
/// blocking path in this kernel shares. A hand-rolled
/// `pending & !mask` here was a second definition of "deliverable" and a
/// wrong one: this kernel keeps ignored signals pending (Linux drops them at
/// send time), so a queued SIG_DFL-ignore signal such as SIGWINCH made every
/// pass return ERESTARTSYS and re-enter, spinning instead of parking.
/// # C: O(N_sig)
fn signal_aborts_wait() -> bool {
    let Some(cur) = sched::live::current() else { return false };
    sched::task::signal_pending_state(&cur, sched::task::WaitState::Interruptible)
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
    crate::user_mem::put_bytes(ptr, &bytes).map_err(|_| crate::user_mem::EFAULT)?;
    Ok(())
}

#[inline]
fn write_wstatus(ptr: u64, val: i32) -> Result<(), i64> {
    if ptr == 0 { return Ok(()); }
    crate::userbuf::validate_user_buf_writable(ptr, 4, 1)?;
    crate::user_mem::put_i32(ptr, val).map_err(|_| crate::user_mem::EFAULT)?;
    Ok(())
}
