// `prctl(PR_SET_SYSCALL_USER_DISPATCH)` EXECUTION — the half of Linux
// `kernel/entry/syscall_user_dispatch.c syscall_user_dispatch()` that reads
// the selector, rolls the syscall back and raises the signal.
//
// The decision (range predicate, selector ladder, mode encoding) lives in
// `sched::prctl::sud`, ungated and hosted-tested; only the effects are here,
// because `sched` cannot reach `do_exit` or the signal-force path without a
// crate cycle (`docs/53`, same split as the seccomp gate next door).
#![cfg(target_os = "oxide-kernel")]

use sched::Signum;
use sched::prctl::sud::{self, Action};
use security::seccomp::native_audit_arch;

/// `si_code` for a syscall-user-dispatch `SIGSYS`
/// (`SYS_USER_DISPATCH`, `include/uapi/asm-generic/siginfo.h`). Distinct from
/// the seccomp code so a handler can tell which mechanism trapped it.
const SYS_USER_DISPATCH: i32 = 2;

/// Run the registration test for the syscall about to dispatch.
///
/// `Some(rv)` means the syscall is SKIPPED and `rv` goes to userspace;
/// `None` means dispatch normally. Linux's `syscall_rollback` on x86_64 is
/// `regs->ax = regs->orig_ax`, i.e. the syscall NUMBER is what a returning
/// SIGSYS handler observes in the return register — the same convention the
/// seccomp `RET_TRAP` path uses here.
/// # C: O(1)
pub(super) fn user_dispatch_gate(nr: u64) -> Option<u64> {
    let cur = sched::live::current()?;
    let cfg = cur.syscall_dispatch.armed()?;
    let pc = crate::arch_frame::current_user_pc();
    // Only read the selector byte when the range test did not already exempt
    // this PC — the common in-dispatcher case must not touch user memory.
    let byte = if cfg.selector != 0 && !sud::pc_is_exempt(&cfg, pc) {
        let mut b = [0u8; 1];
        match uaccess::copy_from_user(&mut b, cfg.selector) { Ok(()) => Some(b[0]), Err(_) => None }
    } else { None };
    match sud::decide(&cfg, pc, byte) {
        Action::Run => None,
        Action::Dispatch => {
            cur.syscall_dispatch.set_on_dispatch();
            raise_sigsys(nr, pc);
            Some(nr)
        }
        // `force_exit_sig(SIGSYS)` / `force_exit_sig(SIGSEGV)` — these are
        // process-fatal and uncatchable, NOT deliverable signals: a selector
        // holding garbage, or one the task unmapped after registering it,
        // cannot be reported to a handler that lives behind the same broken
        // registration.
        Action::KillSigsys => exit_sig(Signum::Sigsys),
        Action::KillSigsegv => exit_sig(Signum::Sigsegv),
    }
}

/// Linux's syscall-EXIT arm: a rolled-back call has an ABI the kernel never
/// interpreted, so the tracer/audit exit work is skipped for it exactly as
/// the entry work was.
/// # C: O(1)
pub(super) fn rolled_back_this_syscall() -> bool {
    sched::live::current().is_some_and(|c| c.syscall_dispatch.take_on_dispatch())
}

/// `trigger_sigsys()` — a CATCHABLE `SIGSYS` carrying the trapping PC and the
/// syscall number, which is the whole point: the userspace dispatcher's
/// handler reads `si_syscall` to decide what to emulate.
fn raise_sigsys(nr: u64, pc: u64) {
    let Some(cur) = sched::live::current() else { return };
    let Some(cur) = sched::registry::lookup(cur.tid) else { return };
    let info = sched::SigInfo {
        signo: Signum::Sigsys as u32,
        code:  SYS_USER_DISPATCH,
        pid:   0,
        uid:   0,
        value: 0,
        sys:   Some(hal::Sigsys {
            call_addr: pc, syscall: nr as i32, arch: native_audit_arch(), errno: 0,
        }),
        fault: None,
        poll:  None,
    };
    // `force_sig_info` semantics: an installed handler still runs, but a
    // BLOCKED or SIG_IGN'd SIGSYS is unblocked and reset to SIG_DFL, so a
    // dispatcher cannot mask the very signal it registered for and then run
    // the foreign syscall natively.
    sched::live::force_sig_info_to_task(&cur, info, sched::sigsend::ForceMode::Current);
}

fn exit_sig(sig: Signum) -> ! {
    crate::s060_exit::do_exit(sched::signum::killed_status(sig.as_u8() as u32));
    sched::live::terminate_current_with_signal(sig.as_u8())
}
