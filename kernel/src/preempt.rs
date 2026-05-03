// Preempt-on-IRQ-exit per `13§9` / `22§4` / `14§R07`.
//
// Per-vector IRQ stub flow:
//   save scratch + vec/err + iretq frame on current task's kernel stack
//   call oxide_irq_dispatch    (sets NEED_RESCHED on timer tick / wake)
//   if NEXT_CTX is non-null:
//     call oxide_context_switch(CUR_CTX, NEXT_CTX)
//     # ret on NEW task's stack lands at oxide_irq_resume_user
//   jmp oxide_irq_resume_user  # pop scratch + drop vec/err + iretq
//
// Rust dispatcher's contract: on entry, NEED_RESCHED reflects whether
// any wakeup/tick-driven event wants a switch. If yes (and policy
// agrees this CPU should switch now), the dispatcher writes
// NEXT_CTX = pick_next_task(); else leaves NEXT_CTX null. The asm
// then either context-switches or drops straight into the epilogue.

use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

/// Set by reschedule events (timer tick, wakeup outranks current,
/// preempt enable). Drained by the Rust dispatcher when it picks
/// next, or by the cooperative `tick_yield()` voluntary path.
pub static NEED_RESCHED: AtomicBool = AtomicBool::new(false);

/// Currently-running task's `Context` record. The IRQ epilogue
/// passes this as `prev` to `oxide_context_switch` when a switch
/// is wanted. Updated by the dispatcher (or the boot edge) when a
/// switch is committed.
///
/// `*mut u8` rather than `*mut ArchCtx` to keep the symbol arch-
/// agnostic from the linker's view; the asm side reads it as an
/// 8-byte raw pointer.
#[no_mangle]
pub static oxide_preempt_cur_ctx: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

/// Scratch slot the dispatcher writes when it wants a switch on
/// IRQ exit. Null = no switch (asm drops straight into the
/// epilogue). The asm clears this slot after consuming it so the
/// next IRQ starts from a clean baseline.
#[no_mangle]
pub static oxide_preempt_next_ctx: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

/// IRQ-exit hook: dispatcher calls this after EOI to ask the
/// scheduler to pick the next task and stage it in
/// `oxide_preempt_next_ctx`. Bridges to `sched::schedule_from_irq`
/// per `14§R07`. No-op when no runqueue is installed (boot phase
/// pre-`install_default_runqueue`).
/// # SAFETY: caller is in IRQ context with IRQs masked.
/// # C: O(log N) CFS pick + O(1) stage; O(1) when no runqueue.
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn tick_pick_next() {
    // SAFETY: caller asserts IRQ context, IRQs masked, single-CPU.
    unsafe { crate::sched::schedule_from_irq(); }
}

/// IRQ-exit hook stub for non-kernel builds (host tests of the
/// `kernel` crate's pure-logic helpers).
/// # SAFETY: trivially safe — no state touched.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub unsafe fn tick_pick_next() {}

/// Reads + clears the flag. Used by the cooperative `tick_yield()`
/// voluntary-yield path (safe-point post-`hlt`/`wfi` wake on tasks
/// that haven't been preempted at the IRQ tail). Real preemption
/// rides through `oxide_preempt_next_ctx`; this remains as a
/// fallback for paths that explicitly poll.
/// # C: O(1)
pub fn need_resched() -> bool {
    NEED_RESCHED.swap(false, Ordering::AcqRel)
}
