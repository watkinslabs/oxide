// seccomp verdict EXECUTION — the half of `__seccomp_filter`
// (`kernel/seccomp.c`) that kills, signals and logs.
//
// The decision itself belongs to `security::seccomp` (`docs/53` hollow
// shell); it lives there because it is pure and hosted-testable. It lives
// there and NOT here because a `#[cfg(test)]` block in this file would be
// compiled out by the `oxide-kernel` gate below and silently reported as
// passing. Only the effects — `do_exit`, `force_sig`, the coredump hook —
// are here, because `security` cannot reach them without a crate cycle.
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;

use sched::Signum;
use security::seccomp::{Sigsys, Verdict, SYS_SECCOMP};

use crate::s101_ptrace_uapi as ptrace_uapi;

/// Run the filter chain for the syscall about to dispatch and carry out the
/// verdict. `Some(rv)` means the syscall is SKIPPED and `rv` goes to
/// userspace; `None` means dispatch normally.
///
/// `nr` is the syscall number AS THE CALLING ABI NUMBERS IT — `seccomp_data.nr`
/// must be the arm64 number an arm64 caller used, not this dispatcher's
/// internal x86_64 translation, or every libseccomp filter compiled for arm64
/// misses every comparison and falls through to its default action.
/// # C: O(F x I)
pub(super) fn seccomp_gate(nr: u64, args: &[u64; 6]) -> Option<u64> {
    // `populate_seccomp_data`'s `instruction_pointer = KSTK_EIP(current)`.
    let ip = crate::arch_frame::current_user_pc();
    match security::seccomp::check(nr, args, ip) {
        Verdict::Allow => None,
        Verdict::Log { syscall } => { log_action(syscall, b"log"); None }
        Verdict::Skip { ret } => Some(ret as u64),
        // `syscall_rollback(current, current_pt_regs())` then
        // `force_sig_seccomp(this_syscall, data, false)` — a CATCHABLE
        // SIGSYS — then `goto skip`. x86_64's `syscall_rollback` is
        // `regs->ax = regs->orig_ax`, so a handler that returns sees the
        // syscall number in the return register.
        Verdict::Trap(s) => { queue_sigsys(&s); Some(nr) }
        // `if (action != SECCOMP_RET_KILL_THREAD ||
        //      atomic_read(&current->signal->live) == 1)` -> fatal SIGSYS
        // with a core dump for the whole group; else `do_exit(SIGSYS)` for
        // this thread alone.
        Verdict::KillThread(s) => {
            log_action(s.syscall, b"kill_thread");
            if last_live_thread() { kill_group_sigsys(&s) } else { exit_thread(Signum::Sigsys) }
        }
        Verdict::KillProcess(s) => { log_action(s.syscall, b"kill_process"); kill_group_sigsys(&s) }
        Verdict::TraceStop { data } => trace_stop(nr, data),
        // `__secure_computing_strict`'s violation path and the MODE_DEAD arm.
        Verdict::DieSigkill => exit_thread(Signum::Sigkill),
    }
}

/// `atomic_read(&current->signal->live) == 1` — this is the last live thread,
/// so killing "the thread" kills the process either way and Linux takes the
/// core-dumping arm.
fn last_live_thread() -> bool {
    match sched::live::current() { Some(c) => c.thread_group.live_count() <= 1, None => true }
}

/// `force_sig_seccomp(this_syscall, data, true)` — `HANDLER_EXIT`, i.e. a
/// fatal SIGSYS that the task cannot catch or block, with a core dump. Takes
/// the whole thread group down.
fn kill_group_sigsys(s: &Sigsys) -> ! {
    // The dying task never returns to userspace, so the `_sigsys` siginfo has
    // no handler to reach; it goes to the log, which is where a killed
    // sandbox's post-mortem starts.
    log_sigsys(s);
    ::fs::coredump::write_for_current(Signum::Sigsys as i32);
    sched::live::terminate_current_with_signal(Signum::Sigsys.as_u8())
}

/// `do_exit(sig)` — this THREAD only; siblings and the thread group survive.
fn exit_thread(sig: Signum) -> ! {
    crate::s060_exit::do_exit(sched::signum::killed_status(sig.as_u8() as u32));
    // `do_exit` schedules away and never returns for a live task.
    sched::live::terminate_current_with_signal(sig.as_u8())
}

/// Queue the CATCHABLE `SIGSYS` of `SECCOMP_RET_TRAP` with the `_sigsys`
/// siginfo arm `force_sig_seccomp` fills. Delivered at the syscall-return
/// tail; `SIG_DFL` for SIGSYS is terminate, so an unhandled trap still kills.
fn queue_sigsys(s: &Sigsys) {
    // NOT logged: `seccomp_log`'s TRAP/ERRNO/TRACE/USER_NOTIF cases are
    // `requested && ...`, and `requested` is the per-filter
    // `SECCOMP_FILTER_FLAG_LOG` bit. Only RET_LOG and the RET_KILL_* pair are
    // logged unconditionally under the default `seccomp_actions_logged`.
    let Some(cur) = sched::live::current() else { return };
    let Some(cur) = sched::registry::lookup(cur.tid) else { return };
    // Linux `force_sig_seccomp(..., force_coredump = false)` — `HANDLER_CURRENT`:
    // an installed SIGSYS handler still runs, but a BLOCKED or SIG_IGN'd SIGSYS
    // is forcibly unblocked and reset to SIG_DFL. The open-coded push this
    // replaced let a filtered process block SIGSYS and sail past every RET_TRAP.
    let info = sched::SigInfo {
        signo: Signum::Sigsys as u32,
        code:  SYS_SECCOMP,
        pid:   0,
        uid:   0,
        value: 0,
        sys:   Some(*s), fault: None, poll: None
    };
    sched::live::force_sig_info_to_task(&cur, info, sched::sigsend::ForceMode::Current);
}

/// `ptrace_event(PTRACE_EVENT_SECCOMP, data)` — stop and report the event
/// with `data` as the `PTRACE_GETEVENTMSG` message.
///
/// After the tracer resumes us Linux re-reads the syscall number and skips
/// the call when the tracer set it negative (`this_syscall =
/// syscall_get_nr(...); if (this_syscall < 0) goto skip;`), which is how a
/// tracer DENIES a `SECCOMP_RET_TRACE` call.
fn trace_stop(nr: u64, data: u16) -> Option<u64> {
    let cur = sched::live::current()?;
    cur.ptrace_eventmsg.store(data as u64, Ordering::Release);
    let stop_code = Signum::Sigtrap as i32
        | ((ptrace_uapi::EVENT_SECCOMP as i32) << 8);
    *cur.ptrace_siginfo.lock() = Some(sched::SigInfo {
        signo: Signum::Sigtrap as u32,
        code:  stop_code,
        pid:   cur.traced_by.load(Ordering::Acquire),
        uid:   0, value: 0, sys: None, fault: None, poll: None
    });
    crate::ptrace_fpu::snapshot_current();
    sched::live::send_signal_self(Signum::Sigtrap);
    // Parks THIS task until the tracer resumes it, exactly as
    // `ptrace_syscall_stop_if_armed` does from the same dispatch head.
    sched::live::stop::stop_until_cont_sig(stop_code as u8);
    crate::ptrace_fpu::restore_if_dirty();
    // "The delivery of a fatal signal during event notification may silently
    // skip tracer notification ... we just force the syscall to be skipped."
    if cur.sigpending.load(Ordering::Acquire) & Signum::Sigkill.bit() != 0 {
        return Some(enosys());
    }
    // The tracer may have rewritten the syscall number; a negative one means
    // "skip this call".
    if tracer_rewrote_nr_negative(nr) { return Some(enosys()); }
    None
}

/// Re-read the syscall number from the live entry frame after a
/// `PTRACE_EVENT_SECCOMP` stop. Only the "tracer set it negative to skip the
/// call" answer is acted on; re-dispatching a DIFFERENT number would need the
/// dispatcher to restart, which it cannot do from here.
fn tracer_rewrote_nr_negative(orig: u64) -> bool {
    let regs = crate::arch_frame::current_user_regs();
    if regs.is_null() { return false; }
    // SAFETY: `current_user_regs` is this task's live syscall entry frame on its own kstack; read-only.
    let now = unsafe { crate::arch_frame::frame_syscall_nr(regs) };
    now != orig && (now as i64) < 0
}

fn enosys() -> u64 { (-(syscall::errno::Errno::Enosys.as_i32() as i64)) as u64 }

/// `seccomp_log(this_syscall, signr, action, requested)` -> `audit_seccomp`.
/// No audit subsystem yet, so the record goes to klog; `SECCOMP_RET_ALLOW` is
/// never logged, matching `seccomp_log`'s first case.
fn log_sigsys(s: &Sigsys) {
    klog::write_raw(b"[SECCOMP] sigsys syscall=");
    klog::write_dec_u64(s.syscall as i64 as u64);
    klog::write_raw(b" arch=");  klog::write_hex_u64(s.arch as u64);
    klog::write_raw(b" ip=");    klog::write_hex_u64(s.call_addr);
    klog::write_raw(b" errno="); klog::write_dec_u64(s.errno as i64 as u64);
    klog::write_raw(b"\n");
}

fn log_action(syscall: i32, action: &'static [u8]) {
    klog::write_raw(b"[SECCOMP] action=");
    klog::write_raw(action);
    klog::write_raw(b" syscall=");
    klog::write_dec_u64(syscall as i64 as u64);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
    klog::write_raw(b"\n");
}
