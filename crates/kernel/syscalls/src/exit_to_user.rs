// Return-to-user-mode work loop — the EXECUTOR half.
//
// Linux `kernel/entry/common.c` `__exit_to_user_mode_loop`. One body, reached
// from EVERY return to user mode:
//
//   * syscall return  — `dispatch/core.rs` tail (Linux
//                       `syscall_exit_to_user_mode_prepare`)
//   * IRQ return      — `arch-irq` `oxide_irq_exit_to_user` on both arches
//                       (Linux `irqentry_exit` -> `irqentry_exit_to_user_mode`)
//   * exception return — the user-mode arm of each arch's fault vector
//
// Before B1471 only the syscall tail existed, so a task that never entered the
// kernel never reached a delivery point: a userspace spin loop took no
// SIGUSR1, ignored its own `alarm(2)` and survived SIGKILL.
//
// The DECISIONS (which work is pending, does the loop repeat, does a
// kernel-mode return run it at all) live ungated in `sched::exit_to_user` and
// are host-unit-tested there; this file is the gated mechanism.
//
// Module manifest:
//   `signal` — Linux `arch_do_signal_or_restart`: dequeue, deliver, and the
//              syscall-restart arm.

#![cfg(target_os = "oxide-kernel")]

pub mod signal;

use core::sync::atomic::Ordering;
use sched::exit_to_user::work;
use sync::IrqGate;

pub use crate::arch_frame::UserRegs;

#[cfg(target_arch = "x86_64")]
type ArchIrqGate = hal_x86_64::X86IrqGate;
#[cfg(target_arch = "aarch64")]
type ArchIrqGate = hal_aarch64::ArmIrqGate;

/// Linux `user_mode(regs)`: `!!(regs->cs & 3)` on x86_64
/// (`arch/x86/include/asm/ptrace.h`), `(regs->pstate & PSR_MODE_MASK) ==
/// PSR_MODE_EL0t` on arm64 (`arch/arm64/include/asm/ptrace.h`). The ONE place
/// either test is written — every return path asks this rather than
/// re-deriving `& 3` / `& 0xf` at the call site.
/// # SAFETY: `regs` is a live entry frame.
/// # C: O(1)
pub unsafe fn user_mode(regs: *const UserRegs) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        use hal::uregs::x86_64::{X86_CS_RPL_MASK, X86_CS_RPL_USER};
        // SAFETY: caller's contract — `regs` is a live entry frame carrying a
        // CPU-pushed CS selector.
        let cs = unsafe { (*regs).cs };
        (cs & X86_CS_RPL_MASK) == X86_CS_RPL_USER
    }
    #[cfg(target_arch = "aarch64")]
    {
        use hal::uregs::aarch64::{PSR_MODE_EL0T, PSR_MODE_MASK};
        // SAFETY: same contract; `spsr_el1` is the saved PSTATE.
        let pstate = unsafe { (*regs).spsr_el1 };
        (pstate & PSR_MODE_MASK) == PSR_MODE_EL0T
    }
}

/// The interrupted context's syscall-return register — `rax` on x86_64, `x0`
/// on aarch64. Linux's `setup_sigframe` copies the WHOLE register set into the
/// signal frame and `handle_signal` overwrites that one slot only for the
/// syscall-restart arms; on an interrupt or exception return there is no
/// syscall, so the register holds ordinary user data and must be recorded
/// verbatim.
///
/// Getting this wrong is silent and severe: B1471's first arm64 differential
/// run delivered SIGUSR1 into a spin loop correctly, then `rt_sigreturn`
/// restored `x0 = 0` because the delivery had recorded a syscall return value
/// that did not exist — the resumed loop dereferenced its `stop` pointer,
/// which lived in x0, and took a NULL data abort.
/// # SAFETY: `regs` is a live entry frame.
/// # C: O(1)
unsafe fn frame_retval(regs: *const UserRegs) -> i64 {
    // SAFETY: caller's contract — `regs` is a live entry frame.
    #[cfg(target_arch = "x86_64")]
    { unsafe { (*regs).rax as i64 } }
    // SAFETY: same contract; `gp[0]` is the saved x0 slot.
    #[cfg(target_arch = "aarch64")]
    { unsafe { (*regs).gp[0] as i64 } }
}

/// Linux `read_thread_flags() & EXIT_TO_USER_MODE_WORK`, read with interrupts
/// masked so the value the loop acts on cannot go stale before the final
/// re-check (`exit_to_user_mode_prepare`'s `lockdep_assert_irqs_disabled`).
/// # C: O(1)
fn work_flags() -> u32 {
    let Some(cur) = sched::live::current() else { return 0 };
    // `should_resched` is the ONE owner of "a reschedule is wanted AND this is
    // a safe point"; it is a pure read, so the flag is consumed only by the
    // pass that actually schedules.
    let need_resched = sched::preempt::should_resched();
    let pending = cur.sigpending.load(Ordering::Acquire);
    let blocked = cur.sigmask.load(Ordering::Acquire);
    // `NOTIFY_RESUME` is Linux's `resume_user_mode_work()`. Never set on this
    // port: there is no `task_work` queue and no blkcg/memcg association to
    // release, so nothing can raise it.
    //
    // `RSEQ` is the rseq user-area writeback. It reports a STANDING condition
    // (the thread registered an rseq area), which is exactly why Linux keeps
    // `_TIF_RSEQ` out of `EXIT_TO_USER_MODE_WORK_LOOP` — as a loop condition
    // it never clears and every return burns the pass bound. It rides along on
    // a pass another item earned; the syscall tail calls `rseq_writeback()`
    // directly before this loop, so a return with no other work still gets it.
    let rseq = cur.rseq_ptr.load(Ordering::Acquire) != 0;
    sched::exit_to_user::work_flags(need_resched, pending, blocked, false, rseq)
}

/// Linux `exit_to_user_mode_loop(regs, ti_work)`.
///
/// `syscall_rv` is `Some` only on the syscall return path — Linux's
/// "did we come from a system call?" (`syscall_get_nr(regs) != -1` inside
/// `arch_do_signal_or_restart`). It gates the ERESTART* handling: an interrupt
/// return has no interrupted syscall to restart, and its return-value register
/// holds an ordinary user value that must not be rewritten.
///
/// Returns the value the syscall dispatcher should hand back; meaningless (and
/// ignored) when `syscall_rv` is `None`.
///
/// Interrupt discipline matches `__exit_to_user_mode_loop`: each pass runs its
/// work with interrupts ENABLED (delivery writes user memory and can fault;
/// `schedule()` must be able to take a tick), then masks them again before
/// re-reading the flags, so a signal posted after the last check is seen by
/// this loop rather than waiting for the next kernel entry.
///
/// # SAFETY: caller is a return-to-user path on the running task's own kernel
/// stack — never the per-CPU hardirq stack, and never with the hardirq
/// accounting still raised. `regs` is that path's live frame.
/// # C: O(1) per pass; passes bounded by `sched::exit_to_user::MAX_PASSES`
/// # Ctx: return-to-user
/// # Sleeps: yes — `schedule()` and a faulting frame write both can
pub unsafe fn exit_to_user_mode_loop(regs: *mut UserRegs, syscall_rv: Option<i64>) -> u64 {
    let from_syscall = syscall_rv.is_some();
    // No interrupted syscall ⇒ the return-value register is ordinary user
    // state, and a signal frame built here must record what is actually in it.
    // SAFETY: caller's contract — `regs` is this return's live entry frame.
    let mut rv = match syscall_rv { Some(v) => v, None => unsafe { frame_retval(regs) } };
    // Linux enters `arch_do_signal_or_restart` on `_TIF_SIGPENDING`; a syscall
    // that returned an ERESTART* sentinel needs the same entry even when the
    // signal was consumed elsewhere (group-exit latch, a racing dequeue), which
    // is that function's `get_signal() == 0` arm. Without this the internal
    // -512/-514/-516 sentinel would reach userspace as a bogus errno.
    //
    // `rv` after `rt_sigreturn` is the return-value register restored out of a
    // user-written sigcontext, so a process can steer this test. Linux has the
    // identical exposure — `syscall_get_error(regs)` reads the same restored
    // `regs->ax` — and it is not an escalation: the restart arm only rewinds
    // the saved PC by the syscall instruction's length and reloads the syscall
    // number, and `rt_sigreturn` already lets the process choose its own PC
    // outright.
    let mut owe_signal_arm = from_syscall && syscall::restart::is_restart_code(rv);
    // Set once a delivery rewrote the frame to re-enter a syscall, or seeded
    // the aarch64 handler's first argument: that word must reach the
    // dispatcher's return slot unmodified.
    let mut arch_retval: Option<u64> = None;
    // Only the FIRST pass after a syscall carries a restartable return value;
    // once a delivery has consumed it the frame holds an ordinary value.
    let mut syscall_pass = from_syscall;
    let mut passes: u32 = 0;
    loop {
        let w = work_flags();
        let want_signal = (w & work::SIGPENDING) != 0 || owe_signal_arm;
        let bounded = passes < sched::exit_to_user::MAX_PASSES;
        if !(sched::exit_to_user::should_continue(w, passes) || (want_signal && bounded)) { break; }
        passes += 1;
        // Linux `local_irq_enable()` at the top of the pass: delivery writes
        // user memory and can fault, and `schedule()` must be able to take a
        // tick. The matching mask is the `restore` at the bottom.
        // SAFETY: return-to-user context on the task's own kernel stack, with
        // no lock held and no hardirq field raised; paired 1:1 with `restore`.
        let flags = unsafe { ArchIrqGate::save_enable() };
        if (w & work::NEED_RESCHED) != 0
            && sched::preempt::preempt_count() == 0 && sched::preempt::take_need_resched() {
            // SAFETY: return-to-user safe point — preempt_count is zero, we
            // are on the task's own kernel stack, and no hardirq field is
            // raised, so this is Linux's `schedule()` from the work loop.
            unsafe { sched::live::schedule(); }
        }
        if want_signal {
            owe_signal_arm = false;
            // SAFETY: forwarded contract — `regs` is the live entry frame and
            // this pass exclusively owns it.
            let out = unsafe { signal::do_signal_or_restart(regs, rv, syscall_pass) };
            rv = out.rv;
            if out.arch_retval.is_some() { arch_retval = out.arch_retval; }
            syscall_pass = false;
        }
        if (w & work::RSEQ) != 0 { crate::proc::rseq_writeback(); }
        // Linux `local_irq_disable()` before re-reading the flags: without it a
        // signal posted between the last check and the `iretq`/`eret` waits for
        // the next kernel entry, which for a spin loop is never.
        // SAFETY: restores the interrupt state this pass saved.
        unsafe { ArchIrqGate::restore(flags); }
    }
    if passes >= sched::exit_to_user::MAX_PASSES {
        klog::write_raw(b"[BUG] exit_to_user_mode_loop: work never cleared\n");
    }
    match arch_retval {
        Some(v) => v,
        None => syscall::restart::normalize_user_return(rv) as u64,
    }
}

/// The registered `sched::exit_to_user::hook` body: Linux `irqentry_exit`.
/// Kernel-mode returns take the other arm and do nothing — an interrupt that
/// hit kernel code has no user register set to deliver into.
///
/// # SAFETY: invoked from an arch IRQ/exception exit with interrupts masked,
/// the hardirq accounting already dropped, and `regs` the live entry frame on
/// the interrupted task's own kernel stack.
/// # C: O(1) plus the work serviced
/// # Ctx: return-to-user
pub unsafe extern "C" fn irqentry_exit(regs: *mut u8) {
    let regs = regs as *mut UserRegs;
    if regs.is_null() { return; }
    // SAFETY: caller's contract — `regs` is a live entry frame.
    if !unsafe { user_mode(regs) } { return; }
    // A kernel thread has no user frame to deliver into even when the saved
    // mode says user (it never reaches here), and a task-less early-boot IRQ
    // has no signal state at all.
    if sched::live::current().is_none() { return; }
    // SAFETY: forwarded contract.
    let _ = unsafe { exit_to_user_mode_loop(regs, None) };
}

/// Install the loop. Boot path, before the first interrupt can be taken from
/// user mode.
/// # SAFETY: called once from the single-CPU boot path.
/// # C: O(1)
pub unsafe fn install() {
    // SAFETY: `irqentry_exit` has the registry's ABI and 'static lifetime.
    unsafe { sched::exit_to_user::hook::set_hook(irqentry_exit); }
}
