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

use core::sync::atomic::AtomicPtr;

// `NEED_RESCHED` lives in `crate::preempt` per `13§9` so the
// preempt-enable check and IRQ-tail check share one flag. The
// kernel-side `set_need_resched` / `take_need_resched` shims just
// forward to that crate.

/// Set need-resched. Called from timer tick + wakeup paths.
/// # C: O(1)
pub fn set_need_resched() { crate::preempt::set_need_resched() }

/// Clear need-resched + report prior. Used by the cooperative
/// `tick_yield()` and IRQ-tail dispatcher.
/// # C: O(1)
pub fn clear_need_resched() -> bool { crate::preempt::take_need_resched() }

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
/// `oxide_preempt_next_ctx`. Bridges to `crate::schedule_from_irq`
/// per `14§R07`. No-op when no runqueue is installed (boot phase
/// pre-`install_default_runqueue`).
/// # SAFETY: caller is in IRQ context with IRQs masked.
/// # C: O(log N) CFS pick + O(1) stage; O(1) when no runqueue.
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn tick_pick_next() {
    // Per `13§9` IRQ-exit preemption: only fire schedule_from_irq
    // when need_resched is set (a tick / wakeup actually requested
    // a switch) AND preempt_count == 0 (no kernel critical section
    // is on this CPU's stack). Otherwise we'd thrash on every tick
    // even when the runnable set hasn't changed.
    if !crate::preempt::take_need_resched() { return; }
    if crate::preempt::preempt_count() != 0 {
        // Re-arm — a preempt-enable will retry once the stack is
        // safe to switch on.
        crate::preempt::set_need_resched();
        return;
    }
    // SAFETY: caller asserts IRQ context, IRQs masked, single-CPU; resched gate above ensured this is the right moment to switch.
    unsafe { crate::live::schedule_from_irq(); }
}

/// IRQ-exit hook stub for non-kernel builds (host tests of the
/// `kernel` crate's pure-logic helpers).
/// # SAFETY: trivially safe — no state touched.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub unsafe fn tick_pick_next() {}

/// Reads + clears the shared `NEED_RESCHED` flag. Forwards to
/// `crate::preempt::take_need_resched`.
/// # C: O(1)
pub fn need_resched() -> bool { crate::preempt::take_need_resched() }
