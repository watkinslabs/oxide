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
/// `oxide_preempt_next_ctx`. No-op when `debug-sched` is off (no
/// kthread scheduler installed in v1; only the smoke surface
/// builds the scheduler state).
/// # SAFETY: caller is in IRQ context with IRQs masked.
/// # C: O(n_kthreads) within the smoke; O(1) when no scheduler.
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
pub unsafe fn tick_pick_next() {
    // SAFETY: caller asserts IRQ context; ksched picks next + stages
    // the pointer pair in `oxide_preempt_{cur,next}_ctx`.
    unsafe { crate::ksched::tick_pick_next_for_irq_exit(); }
}

/// IRQ-exit hook stub for builds without the kthread scheduler.
/// # SAFETY: trivially safe — no state touched.
/// # C: O(1)
#[cfg(any(not(target_os = "oxide-kernel"), not(feature = "debug-sched")))]
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
