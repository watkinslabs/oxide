// Syscall-return-tail signal dispatch — extracted from signal.rs to
// honor `08§7` file-length cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use sched::live::sigpend::Signum;
use crate::signal::PendingSignal;

/// `kernel-internal` SIG_DFL / SIG_IGN sentinel values — match the
/// Linux uapi sa_handler convention. NEVER inline these as bare 0/1
/// literals at call sites (CLAUDE.md `07§5`).
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;

/// B117: build the `hal::SigChld` siginfo payload for a SIGCHLD
/// PendingSignal, mapping the dequeued `sched::SigInfo` child event
/// (pid=child VPID, value=child exit status, code=CLD_*) onto the
/// arch-neutral `_sigchld` fields the frame builder writes. `None`
/// for non-SIGCHLD or a SIGCHLD with no queued child event (e.g.
/// `kill(pid, SIGCHLD)` — no child exited).
/// # C: O(1)
#[inline]
fn sigchld_payload(p: &PendingSignal) -> Option<hal::SigChld> {
    // SIGCHLD carries child-exit fields; RT signals (33..=64) carry the SENDER's
    // pid/uid + si_code (SI_TKILL / SI_QUEUE). SA_SIGINFO handlers read these:
    // glibc's __nptl_setxid_sighandler (SIGSETXID=33) rejects the signal unless
    // `si_pid == getpid() && si_code == SI_TKILL`, so a zeroed siginfo made it
    // return without applying the setxid or acking — setgid()/setresgid() in a
    // multithreaded process (gdm-session-worker) then hung in __nptl_setxid. The
    // sender's siginfo is queued at send time (tgkill/rt_sigqueue); thread it
    // into the frame for RT signals too, not just SIGCHLD.
    if p.sig as u8 != Signum::Sigchld as u8 && !sched::signum::is_realtime(p.sig) {
        return None;
    }
    let i = p.info?;
    Some(hal::SigChld { code: i.code, pid: i.pid as i32, uid: i.uid, status: i.value as i32 })
}

/// Dispatch one PendingSignal at the syscall-return tail. Returns
/// the value the dispatcher should propagate as its u64 retval —
/// nonzero only when a handler was set up on aarch64 (the SVC
/// restore asm uses retval to seed user x0 → handler's first AAPCS64
/// arg). x86 injects sig directly into the saved-rdi slot and
/// returns 0 here.
/// # SAFETY: caller is the syscall-return tail; per-arch saved frame
/// is live; sys_exit_fn passed by mod.rs (avoids module cycle).
/// # C: O(1)
pub unsafe fn dispatch_pending(p: &PendingSignal, saved_ret: u64, sys_exit_fn: &dyn Fn(&SyscallArgs) -> i64) -> u64 {
    // SIGCONT — default no-op (process continues running). User
    // handler dispatches normally; SIG_DFL / SIG_IGN silently drop.
    if p.sig as u8 == Signum::Sigcont as u8 {
        if p.handler != SIG_DFL && p.handler != SIG_IGN {
            // SAFETY: same dispatch-tail context as the handler arm below.
            let sig_rv = unsafe { ::fs::sig_dispatch::deliver(p.handler, p.restorer, p.sig, saved_ret) };
            #[cfg(target_arch = "aarch64")]
            return sig_rv;
            #[cfg(not(target_arch = "aarch64"))]
            { let _ = sig_rv; return 0; }
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
                // Linux: a fatal signal terminates the WHOLE thread group
                // (`get_signal` → `do_group_exit`), not just the thread that
                // took it. SIGKILL the siblings first so a multi-threaded
                // process can't leave threads alive holding the dead thread's
                // libc locks (the deadlock/wedge), then exit the caller.
                sched::live::zap_other_threads();
                // killed_status encodes the wait4/waitid "killed by signal"
                // status (signo + WSTATUS_SIGNALED, + WSTATUS_CORE for the
                // core-dumping signals) so the parent reaps WIFSIGNALED /
                // WCOREDUMP / CLD_KILLED-vs-CLD_DUMPED correctly.
                let exit_args = SyscallArgs {
                    a0: killed_status(p.sig) as u64, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0,
                };
                let _ = sys_exit_fn(&exit_args);
            }
            0
        }
        SIG_IGN => 0,  // explicit ignore: drop
        handler => {
            // B117: for SIGCHLD pass the dequeued child-exit siginfo
            // so an SA_SIGINFO handler reads si_pid/si_status/si_code.
            let chld = sigchld_payload(p);
            // SAFETY: dispatch tail; per-arch saved frame live; deliver_arm/_x86 rewrites only the saved frame and user signal stack.
            let sig_rv = unsafe { ::fs::sig_dispatch::deliver_with_info(handler, p.restorer, p.sig, saved_ret, chld) };
            #[cfg(target_arch = "aarch64")]
            return sig_rv;
            #[cfg(not(target_arch = "aarch64"))]
            { let _ = sig_rv; 0 }
        }
    }
}
