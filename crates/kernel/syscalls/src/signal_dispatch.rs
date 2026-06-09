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

/// Default action = IGNORE per signal(7).
#[inline]
fn default_is_ignore(sig: u32) -> bool {
    let s = sig as u8;
    s == Signum::Sigchld as u8
        || s == Signum::Sigurg as u8
        || s == Signum::Sigwinch as u8
}

/// Default action = TERMINATE-WITH-CORE per signal(7) — produces a
/// core file on top of the kill.
#[inline]
fn default_is_core(sig: u32) -> bool {
    let s = sig as u8;
    s == Signum::Sigquit as u8
        || s == Signum::Sigill  as u8
        || s == Signum::Sigtrap as u8
        || s == Signum::Sigabrt as u8
        || s == Signum::Sigbus  as u8
        || s == Signum::Sigfpe  as u8
        || s == Signum::Sigsegv as u8
        || s == Signum::Sigxcpu as u8
        || s == Signum::Sigxfsz as u8
        || s == Signum::Sigsys  as u8
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
            // SIG_DFL — signal(7) default action triage.
            if !default_is_ignore(p.sig) {
                if default_is_core(p.sig) {
                    ::fs::coredump::write_for_current(p.sig as i32);
                }
                // Encode wait4(2) "killed by signal" byte: low 7 = signo,
                // bit 7 set on core dump (we approximate with bit 8 the
                // way mark_done's exit_status decodes it).
                let exit_args = SyscallArgs {
                    a0: (p.sig | 0x100) as u64, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0,
                };
                let _ = sys_exit_fn(&exit_args);
            }
            0
        }
        SIG_IGN => 0,  // explicit ignore: drop
        handler => {
            // SAFETY: dispatch tail; per-arch saved frame live; deliver_arm/_x86 rewrites only the saved frame and user signal stack.
            let sig_rv = unsafe { ::fs::sig_dispatch::deliver(handler, p.restorer, p.sig, saved_ret) };
            #[cfg(target_arch = "aarch64")]
            return sig_rv;
            #[cfg(not(target_arch = "aarch64"))]
            { let _ = sig_rv; 0 }
        }
    }
}
