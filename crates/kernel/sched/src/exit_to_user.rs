// Return-to-user-mode work loop — the decision half.
//
// Linux runs the SAME loop before EVERY return to user mode, not just after a
// syscall: `kernel/entry/common.c` `__exit_to_user_mode_loop`, reached from
// `syscall_exit_to_user_mode_prepare` (syscall) and
// `irqentry_exit_to_user_mode_prepare` (interrupt + exception), the latter via
// `irqentry_exit`'s `if (user_mode(regs))` arm. Without it a task that never
// enters the kernel never reaches a delivery point: a pure userspace spin loop
// takes no SIGUSR1, does not honour its own `alarm(2)`, and survives SIGKILL
// (B1471 / `scratch/wait-diff-open-items.md` W9).
//
// This file is PURE DECISION LOGIC with NO target gate, so every rule is
// host-unit-tested. `crates/kernel/sched/src/exit_to_user/hook.rs` carries the
// registry the arch entry paths call through (`arch-irq` cannot depend on
// `syscalls` — `syscalls` already depends on `arch-irq`), and the executor
// that consumes these flags lives in `syscalls::exit_to_user`.
//
// Module manifest:
//   `work`   — the `_TIF_*` bit names and the `EXIT_TO_USER_MODE_WORK` mask.
//   `hook`   — install/read the arch-neutral entry point the IRQ + fault
//              return paths call.

pub mod hook;

/// Linux `_TIF_*` work bits, in `EXIT_TO_USER_MODE_WORK` order
/// (`include/linux/irq-entry-common.h`). One bit per work item the loop can
/// service; the numeric values are private to this kernel — nothing crosses
/// the ABI — but the NAMES track Linux's so the mapping stays checkable.
pub mod work {
    /// Linux `_TIF_NEED_RESCHED` — a reschedule was requested (tick, wakeup,
    /// resched IPI). Serviced by `schedule()`.
    pub const NEED_RESCHED: u32 = 1 << 0;
    /// Linux `_TIF_SIGPENDING` — a deliverable signal is queued. Serviced by
    /// `arch_do_signal_or_restart`.
    pub const SIGPENDING: u32 = 1 << 1;
    /// Linux `_TIF_NOTIFY_RESUME` — `resume_user_mode_work()`. On this port
    /// the only resume work is the rseq user-area writeback; there is no
    /// `task_work` queue and no blkcg/memcg association to release.
    pub const NOTIFY_RESUME: u32 = 1 << 2;
    /// Linux `_TIF_RSEQ` — a restartable-sequence fixup is owed because the
    /// thread lost the CPU (or is about to) inside a declared critical
    /// section. Split from `NOTIFY_RESUME` exactly as Linux split it out of
    /// `_TIF_NOTIFY_RESUME`.
    pub const RSEQ: u32 = 1 << 3;

    /// Linux `EXIT_TO_USER_MODE_WORK` — the set tested to decide whether the
    /// loop is entered at all. `_TIF_UPROBE` and `_TIF_PATCH_PENDING` are
    /// deliberately absent: this kernel has neither uprobes nor livepatching,
    /// so there is no state a bit could describe. `_TIF_NOTIFY_SIGNAL` is
    /// absent for the same reason — it exists in Linux to let `task_work` wake
    /// a task without a real signal, and there is no `task_work` queue here.
    pub const MASK: u32 = NEED_RESCHED | SIGPENDING | NOTIFY_RESUME | RSEQ;

    /// Linux `EXIT_TO_USER_MODE_WORK_LOOP` = `EXIT_TO_USER_MODE_WORK &
    /// ~_TIF_RSEQ` (`kernel/entry/common.c`, `CONFIG_HAVE_GENERIC_TIF_BITS`).
    /// `RSEQ` describes a STANDING condition — the thread registered an rseq
    /// area — not an event a pass consumes, so leaving it in the `while`
    /// condition makes every return spin to the pass bound. Linux carves it
    /// out for precisely that reason and services it outside the loop.
    pub const MASK_LOOP: u32 = MASK & !RSEQ;
}

/// Whether a deliverable signal is pending — Linux `signal_pending()`, whose
/// `TIF_SIGPENDING` is set by `signal_wake_up_state` for exactly the signals
/// `next_signal` would dequeue. Delegates to `signum::next_deliverable` so the
/// "is there work" question and the "which signal" answer can never disagree
/// (SIGKILL/SIGSTOP bypassing the blocked mask is decided in ONE place).
/// # C: O(1)
pub fn signal_pending(pending: u64, blocked: u64) -> bool {
    crate::signum::next_deliverable(pending, blocked).is_some()
}

/// Linux `read_thread_flags() & EXIT_TO_USER_MODE_WORK` — the work word the
/// loop tests, assembled from the live per-task/per-CPU state the caller has
/// already read with interrupts disabled.
/// # C: O(1)
pub fn work_flags(need_resched: bool, sigpending: u64, blocked: u64,
                  notify_resume: bool, rseq: bool) -> u32 {
    let mut w = 0;
    if need_resched { w |= work::NEED_RESCHED; }
    if signal_pending(sigpending, blocked) { w |= work::SIGPENDING; }
    if notify_resume { w |= work::NOTIFY_RESUME; }
    if rseq { w |= work::RSEQ; }
    w
}

/// Linux `while (ti_work & EXIT_TO_USER_MODE_WORK_LOOP)`: the loop condition,
/// re-evaluated after each pass with interrupts disabled. A single check is
/// NOT equivalent — servicing one item runs with interrupts enabled and can
/// queue another (a `schedule()` that comes back with a signal posted, a
/// handler frame build that faults and takes a tick).
///
/// Tests `MASK_LOOP`, not `MASK`: a standing condition must never be a reason
/// to take another pass.
/// # C: O(1)
pub fn has_work(w: u32) -> bool { (w & work::MASK_LOOP) != 0 }

/// Linux `__exit_to_user_mode_prepare`'s `if (unlikely(ti_work & work_mask))`
/// — whether the loop is ENTERED. Wider than `has_work`, since a pass may be
/// owed for a standing item the `while` condition excludes.
/// # C: O(1)
pub fn enters_loop(w: u32) -> bool { (w & work::MASK) != 0 }

/// Linux `irqentry_exit`: `if (user_mode(regs)) irqentry_exit_to_user_mode()`
/// `else irqentry_exit_to_kernel_mode()`. An interrupt or exception that hit
/// KERNEL mode must never run this loop — the interrupted context is a kernel
/// stack frame, not a user register set, so delivering a signal there would
/// build a handler frame over kernel state and `schedule()` would park on a
/// half-finished kernel critical section. Kernel-mode returns get only Linux's
/// `raw_irqentry_exit_cond_resched`, which this port does not enable
/// (`CONFIG_PREEMPT` off ⇒ voluntary preemption only).
/// # C: O(1)
pub fn runs_on_return(from_user: bool, w: u32) -> bool { from_user && enters_loop(w) }

/// One pass of Linux's `__exit_to_user_mode_loop` body, as a decision: given
/// the work word read at the top of the pass, which items does this pass run?
/// Returned as a word so the executor cannot silently skip one — every bit it
/// does not consume is still set on the next `work_flags` read.
///
/// Order matters and matches Linux exactly: `schedule()` first (so a signal is
/// delivered by whichever task actually gets the CPU), then signals, then
/// resume work. rseq is serviced last because `rseq_exit_to_user_mode_restart`
/// re-runs the whole loop when it fires.
/// # C: O(1)
pub fn pass_order() -> [u32; 4] {
    [work::NEED_RESCHED, work::SIGPENDING, work::NOTIFY_RESUME, work::RSEQ]
}

/// Linux caps nothing here — `__exit_to_user_mode_loop` spins until the flags
/// clear, because every producer is finite. This port keeps a bound so a
/// mis-wired producer (a work bit nothing consumes) surfaces as a klog
/// complaint instead of a silent hard hang with interrupts enabled. Chosen far
/// above any legitimate pass count: the only self-feeding item is a signal, and
/// a task cannot have more than the 64 signal slots pending at once.
///
/// The bound has caught exactly one such producer, and the complaint was
/// correct both times it is worth restating: `NEED_RESCHED` used to live in a
/// per-CPU word, so every tick that landed while this task was descheduled came
/// back as this task's request and each pass bought exactly one more
/// (`B1476`). The fix was to put `TIF_NEED_RESCHED` on the task, as Linux has
/// it — NOT to raise the bound.
pub const MAX_PASSES: u32 = 128;

/// Whether the loop should keep going, folding the pass bound in.
/// # C: O(1)
pub fn should_continue(w: u32, passes: u32) -> bool { has_work(w) && passes < MAX_PASSES }

#[cfg(test)]
#[path = "exit_to_user/tests.rs"] mod tests;
