// Syscall-return-tail signal dispatch — extracted from signal.rs to
// honor `08§7` file-length cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use sched::live::sigpend::Signum;

/// Linux `SA_RESTORER`: user supplied the signal-return trampoline.
/// AArch64 handlers without this flag return through the mapped vDSO entry.
const SA_RESTORER: u64 = 0x0400_0000;
/// Linux `SA_RESTART`; caught handlers carrying this flag restart
/// `ERESTARTSYS` syscalls through their preserved signal frame. The
/// syscall-return tail (`dispatch/core.rs`) reads the same constant so the
/// restart decision has one owner.
pub(crate) const SA_RESTART: u64 = 0x1000_0000;
use crate::signal::PendingSignal;

/// `kernel-internal` SIG_DFL / SIG_IGN sentinel values — match the
/// Linux uapi sa_handler convention. NEVER inline these as bare 0/1
/// literals at call sites (CLAUDE.md `07§5`).
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;

/// Pick the Linux AArch64 signal-return continuation. `SA_RESTORER` keeps an
/// explicit userspace trampoline; otherwise arm64 returns through the vDSO
/// `__kernel_rt_sigreturn` mapping owned by the current mm.
#[cfg(target_arch = "aarch64")]
fn aarch64_restorer(p: &PendingSignal) -> Option<u64> {
    if (p.flags & SA_RESTORER) != 0 { Some(p.restorer) }
    else { crate::vdso::current_signal_restorer() }
}

#[cfg(target_arch = "aarch64")]
fn deliver_aarch64(p: &PendingSignal, saved_ret: u64, restart: bool, payload: Option<hal::SigPayload>) -> u64 {
    let Some(restorer) = aarch64_restorer(p) else {
        sched::live::terminate_current_with_signal(Signum::Sigsegv.as_u8());
    };
    #[cfg(feature = "debug-zram-lifecycle")]
    crate::signal_trace::zram_lifecycle_signal_frame(p, restorer);
    debug_ssh! {
        klog::write_raw(b"[INFO] ssh-trace: arm-signal-frame sig=");
        klog::write_dec_u64(p.sig as u64);
        klog::write_raw(b" handler="); klog::write_hex_u64(p.handler);
        klog::write_raw(b" restorer="); klog::write_hex_u64(restorer);
        klog::write_raw(b"\n");
    }
    // SAFETY: dispatch tail; per-task SVC frame and active user AS belong to
    // this task for the whole frame construction.
    unsafe { ::fs::sig_dispatch::deliver_with_info(p.handler, restorer, p.sig, saved_ret, restart, payload, p.flags, p.mask) }
}

/// Build the `hal::SigPayload` siginfo payload from a dequeued
/// `sched::SigInfo`, selecting the `siginfo_t` union arm by signal: SIGCHLD
/// gets `_sigchld` (si_status, an `int`), everything else gets `_rt`
/// (si_value, a full 8-byte `sigval_t` — truncating that to 4 bytes loses the
/// `sival_ptr` a `sigqueue(3)` sender passed).
///
/// EVERY signal with a queued record gets one, not just SIGCHLD and the RT
/// range: glibc's `__nptl_setxid_sighandler` (SIGSETXID) rejects the signal
/// unless `si_pid == getpid() && si_code == SI_TKILL`, so a zeroed siginfo
/// made it return without applying the setxid or acking — `setgid()` in a
/// multithreaded process (gdm-session-worker) then hung in `__nptl_setxid`.
/// Standard signals sent by `sigqueue(3)`/`tgkill(2)` carry the same fields.
/// # C: O(1)
#[inline]
fn siginfo_payload(p: &PendingSignal) -> Option<hal::SigPayload> {
    let i = p.info?;
    let chld_arm = p.sig as u8 == Signum::Sigchld as u8;
    Some(hal::SigPayload {
        code: i.code, pid: i.pid as i32, uid: i.uid,
        status: i.value as i32, value: i.value, chld_arm,
    })
}

/// Dispatch one PendingSignal at the syscall-return tail. Returns
/// the value the dispatcher should propagate as its u64 retval —
/// nonzero only when a handler was set up on aarch64 (the SVC
/// restore asm uses retval to seed user x0 → handler's first AAPCS64
/// arg). x86 injects sig directly into the saved-rdi slot and
/// returns 0 here.
/// # SAFETY: caller is the syscall-return tail; per-arch saved frame is live.
/// # C: O(1)
pub unsafe fn dispatch_pending(p: &PendingSignal, saved_ret: u64) -> u64 {
    // Linux `handle_signal`'s restart switch, evaluated for the frame this
    // delivery builds: ERESTARTSYS restarts only under SA_RESTART,
    // ERESTARTNOINTR restarts unconditionally, ERESTARTNOHAND and
    // ERESTART_RESTARTBLOCK become EINTR once a handler runs.
    let restart = crate::signal::runs_user_handler(p)
        && syscall::restart::signal_restart_action(
               saved_ret as i64, true, (p.flags & SA_RESTART) != 0)
           == syscall::restart::RestartAction::RestartSame;
    // SIGCONT — default no-op (process continues running). User
    // handler dispatches normally; SIG_DFL / SIG_IGN silently drop.
    if p.sig as u8 == Signum::Sigcont as u8 {
        if p.handler != SIG_DFL && p.handler != SIG_IGN {
            // A SIGCONT handler is an ordinary handler: it honours SA_ONSTACK,
            // sa_mask and SA_NODEFER like every other one.
            let payload = siginfo_payload(p);
            #[cfg(target_arch = "aarch64")]
            return deliver_aarch64(p, saved_ret, restart, payload);
            #[cfg(not(target_arch = "aarch64"))]
            {
            // SAFETY: same dispatch-tail context as the handler arm below.
            let sig_rv = unsafe { ::fs::sig_dispatch::deliver_with_info(p.handler, p.restorer, p.sig, saved_ret, restart, payload, p.flags, p.mask) };
            { let _ = sig_rv; return 0; }
            }
        }
        return 0;
    }
    match p.handler {
        SIG_DFL => {
            // SIG_DFL — signal(7) default action triage. Single source of
            // truth in sched::signum so the policy is hosted-tested. Job-control
            // STOP signals are handled in the dispatch tail (dispatch.rs) before
            // we get here; CONT/IGN are no-ops. Only TERM/CORE terminate.
            use sched::signum::{default_action, DefaultAction, killed_status};
            let action = default_action(p.sig);
            if action == DefaultAction::Core {
                ::fs::coredump::write_for_current(p.sig as i32);
            }
            if action == DefaultAction::Core || action == DefaultAction::Term {
                // Linux `get_signal`: a fatal signal terminates the WHOLE
                // thread group via `do_group_exit(ksig->info.si_signo)`, not
                // just the thread that took it. Routing through `do_group_exit`
                // (rather than an open-coded zap + plain exit) is what makes the
                // group report THIS signal: the leader is felled by the SIGKILL
                // the zap posts, re-enters `do_group_exit` with SIGKILL, loses
                // the `SIGNAL_GROUP_EXIT` latch, and reports the original signo.
                // `killed_status` supplies signo + WSTATUS_SIGNALED (+
                // WSTATUS_CORE for the core-dumping signals) so the parent reaps
                // WIFSIGNALED / WCOREDUMP / CLD_KILLED-vs-CLD_DUMPED correctly.
                let _ = crate::s060_exit::do_group_exit(killed_status(p.sig));
            }
            0
        }
        SIG_IGN => 0,  // explicit ignore: drop
        _handler => {
            // B117: for SIGCHLD pass the dequeued child-exit siginfo
            // so an SA_SIGINFO handler reads si_pid/si_status/si_code.
            let payload = siginfo_payload(p);
            #[cfg(target_arch = "aarch64")]
            return deliver_aarch64(p, saved_ret, restart, payload);
            #[cfg(not(target_arch = "aarch64"))]
            {
            // SAFETY: dispatch tail; per-arch saved frame live; deliver_arm/_x86 rewrites only the saved frame and user signal stack.
            let sig_rv = unsafe { ::fs::sig_dispatch::deliver_with_info(_handler, p.restorer, p.sig, saved_ret, restart, payload, p.flags, p.mask) };
            { let _ = sig_rv; 0 }
            }
        }
    }
}
