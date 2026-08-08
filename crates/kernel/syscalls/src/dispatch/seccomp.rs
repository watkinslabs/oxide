// seccomp verdict EXECUTION — the half of `__seccomp_filter`
// that kills, signals and logs.
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
        Verdict::Log { syscall } => {
            audit_action(syscall, security::seccomp::SECCOMP_RET_LOG, 0);
            log_action(syscall, b"log"); None
        }
        Verdict::Skip { ret } => Some(ret as u64),
        // The supervisor is waited for inside `check`, which hands back the
        // outcome as an ordinary verdict, so this arm never arrives. Denying
        // rather than dispatching keeps "a filter that meant the call to be
        // examined never lets it through unexamined" true even here.
        Verdict::UserNotif { .. } => Some(enosys()),
        // `syscall_rollback(current, current_pt_regs())` then
        // `force_sig_seccomp(this_syscall, data, false)` — a CATCHABLE
        // SIGSYS — then `goto skip`. What the rollback leaves in the return
        // register differs per arch, so it is not `nr` on both.
        Verdict::Trap(s) => {
            queue_sigsys(&s);
            Some(crate::syscall_rollback::rolled_back_return(nr, args[0]))
        }
        // `if (action != SECCOMP_RET_KILL_THREAD ||
        //      atomic_read(&current->signal->live) == 1)` -> fatal SIGSYS
        // with a core dump for the whole group; else `do_exit(SIGSYS)` for
        // this thread alone.
        Verdict::KillThread(s) => {
            audit_action(s.syscall, security::seccomp::SECCOMP_RET_KILL_THREAD,
                Signum::Sigsys as u32);
            log_action(s.syscall, b"kill_thread");
            if last_live_thread() { kill_group_sigsys(&s) } else { exit_thread(Signum::Sigsys) }
        }
        Verdict::KillProcess(s) => {
            audit_action(s.syscall, security::seccomp::SECCOMP_RET_KILL_PROCESS,
                Signum::Sigsys as u32);
            log_action(s.syscall, b"kill_process");
            kill_group_sigsys(&s)
        }
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
    // The dump's `NT_SIGINFO` carries the `_sigsys` arm the log just printed —
    // which syscall the filter refused, at which instruction.
    let info = sched::SigInfo {
        signo: Signum::Sigsys as u32, code: SYS_SECCOMP,
        pid: 0, uid: 0, value: 0,
        sys: Some(*s), fault: None, poll: None,
    };
    // SAFETY: this is a return-to-user path on the dying task's own kernel stack, so `current_user_regs` is its live entry frame and no other CPU writes it.
    unsafe {
        ::fs::coredump::write_for_current(Signum::Sigsys as i32,
            crate::arch_frame::current_user_regs(),
            Some(info.payload(Signum::Sigsys as u32)));
    }
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
    // One producer for every PTRACE_EVENT_* stop (`101_ptrace/stop.rs`): it
    // records the message, publishes `last_siginfo` and parks. Open-coding it
    // here truncated the stop code to a byte — `SIGTRAP | (EVENT_SECCOMP << 8)`
    // is 0x705, so the event byte was lost and the tracer's wait status read as
    // a bare SIGTRAP — and queued a real SIGTRAP that outlived the resume.
    crate::ptrace::stop::notify(ptrace_uapi::event_stop_code(ptrace_uapi::EVENT_SECCOMP),
                                data as u64);
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
///
/// The record is the durable account a security policy reads; the klog lines
/// below it are the post-mortem a developer reads when no audit consumer is
/// running. `SECCOMP_RET_ALLOW` reaches neither.
fn audit_seccomp(s: &Sigsys, signal: u32, action: u32) {
    let _ = audit::log_seccomp(audit::SeccompEvent {
        tid: sched::live::current().map(|c| c.tid).unwrap_or(0),
        signal,
        action,
        syscall: s.syscall,
        arch: s.arch,
        ip: s.call_addr,
        errno: s.errno as u32,
    });
}

fn log_sigsys(s: &Sigsys) {
    klog::write_raw(b"[SECCOMP] sigsys syscall=");
    klog::write_dec_u64(s.syscall as i64 as u64);
    klog::write_raw(b" arch=");  klog::write_hex_u64(s.arch as u64);
    klog::write_raw(b" ip=");    klog::write_hex_u64(s.call_addr);
    klog::write_raw(b" errno="); klog::write_dec_u64(s.errno as i64 as u64);
    klog::write_raw(b"\n");
}

/// A verdict that names only the syscall it refused: the record still needs
/// the calling ABI and the instruction, which are read from the live frame.
/// # C: O(1)
fn audit_action(syscall: i32, action: u32, signal: u32) {
    audit_seccomp(&Sigsys {
        call_addr: crate::arch_frame::current_user_pc(),
        syscall,
        arch: security::seccomp::native_audit_arch(),
        errno: 0,
    }, signal, action);
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
