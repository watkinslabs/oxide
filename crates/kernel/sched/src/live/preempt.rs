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

// Per-CPU IRQ-exit context-switch staging (`13§9` / `14§R07`), SMP-safe.
//
// The staging pointer pair lives in THIS CPU's per-CPU area (the page the
// per-CPU base register points at — `gs` on x86, `TPIDR_EL1` on arm), not
// in a shared global, so two CPUs taking IRQs concurrently never clobber
// each other's switch and resume into the wrong task. Layout (offsets from
// the per-CPU base; `cpu_id` is the existing u32 at offset 0):
//
//   [0]  u32   cpu_id              (set by boot / ap_main)
//   [8]  *mut  PERCPU_NEXT_CTX_OFF — next task's Context*, or null = no switch
//   [16] *mut  PERCPU_CUR_CTX_OFF  — current task's Context* (prev → switch arg)
//
// The IRQ-exit asm epilogue (hal-x86_64/irq.rs, hal-aarch64/vbar.rs) reads
// these base-relative; `stage_switch` is the only writer, on the same CPU
// from `schedule_from_irq`. No swapgs on x86 (GS_BASE is always the kernel
// per-CPU base; user TLS uses FS), so the gs-relative read is valid at IRQ
// time exactly as `current_cpu()`'s `gs:0` read already relies on.

/// Per-CPU-area byte offset of the NEXT-context staging slot. Must match
/// the literal `#8` / `[8]` in the IRQ-exit asm epilogues.
pub const PERCPU_NEXT_CTX_OFF: usize = 8;
/// Per-CPU-area byte offset of the CURRENT-context staging slot. Must match
/// the literal `#16` / `[16]` in the IRQ-exit asm epilogues.
pub const PERCPU_CUR_CTX_OFF: usize = 16;

/// Read this CPU's per-CPU base pointer (the per-CPU base register value).
/// Host builds have no per-CPU area → null (stage_switch no-ops there; the
/// staging is only consumed by kernel asm).
/// # C: O(1)
#[inline]
fn percpu_base() -> *mut u8 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let b: u64;
        // SAFETY: rdgsbase reads the kernel GS_BASE (CR4.FSGSBASE enabled at
        // boot; GS_BASE is always the kernel per-CPU area — no swapgs model).
        unsafe { core::arch::asm!("rdgsbase {b}", b = out(reg) b, options(nomem, nostack, preserves_flags)); }
        b as *mut u8
    }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let b: u64;
        // SAFETY: mrs tpidr_el1 reads this CPU's per-CPU area base (set by
        // boot / ap_main); EL1-only register, never touched at EL0.
        unsafe { core::arch::asm!("mrs {b}, tpidr_el1", b = out(reg) b, options(nomem, nostack, preserves_flags)); }
        b as *mut u8
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { core::ptr::null_mut() }
}

/// Stage `(cur, next)` for the IRQ-exit asm to context-switch into on this
/// CPU. Writes the per-CPU area's CUR/NEXT slots; `next = null` means "no
/// switch" (the asm drops straight to the resume epilogue). Sole writer,
/// called from `schedule_from_irq` on the same CPU with IRQs masked.
/// # SAFETY: caller is in IRQ context, IRQs masked; `cur`/`next` alias live
/// `Context` buffers for this CPU's prev/next task.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn stage_switch(cur: *mut u8, next: *mut u8) {
    let base = percpu_base();
    if base.is_null() { return; }
    // SAFETY: base is this CPU's per-CPU area (≥4 KiB; offsets 8/16 reserved
    // for staging per the layout above); single-CPU writer, IRQs masked.
    unsafe {
        core::ptr::write_volatile(base.add(PERCPU_CUR_CTX_OFF)  as *mut *mut u8, cur);
        core::ptr::write_volatile(base.add(PERCPU_NEXT_CTX_OFF) as *mut *mut u8, next);
    }
}

/// Host stub — no per-CPU area / asm epilogue off-kernel.
/// # SAFETY: trivially safe; no state touched.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub unsafe fn stage_switch(_cur: *mut u8, _next: *mut u8) {}

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
