// Per-vector IRQ entry stubs per `22§4` + IRQ-exit preemption epilogue
// per `14§R07`.
//
// Distinct from the fault stubs (`fault.rs`): IRQ stubs save the
// scratch registers, call the Rust dispatcher, optionally switch
// tasks at the tail, then `iretq` back to whatever task we end up
// resuming. The dispatcher does the EOI dance.
//
// The IRQ epilogue (pop scratch + drop synthetic vec/err + iretq)
// is factored into a dedicated symbol `oxide_irq_resume_user` so a
// freshly-built task built via `Context::new_kernel_with_irq_frame`
// can store its address as the saved-RIP at the bottom of the
// scaffold; `oxide_context_switch`'s `ret` then lands in the
// epilogue continuation.
//
// Phase-1 scope: a single timer vector (0x40). Wider IRQ table
// rides alongside scheduler bring-up.

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".intel_syntax noprefix",
    ".section .text",

    // ----- per-vector stub -------------------------------------------------
    ".globl oxide_irq_vec_40",
    ".type  oxide_irq_vec_40, @function",
    "oxide_irq_vec_40:",
    "    push 0",                  // synthetic err code (IRQs don't push one)
    "    push 0x40",                // vector tag
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld",
    "    mov rdi, rsp",            // arg 0 = pointer to saved frame
    "    call oxide_irq_dispatch",
    // -- schedule-on-exit per `14§R07`. Rust dispatcher writes
    //    `oxide_preempt_next_ctx` if a switch is wanted; null = stay.
    "    mov  rax, qword ptr [rip + oxide_preempt_next_ctx]",
    "    test rax, rax",
    "    jz   2f",
    "    mov  rdi, qword ptr [rip + oxide_preempt_cur_ctx]",
    "    mov  rsi, rax",
    "    mov  qword ptr [rip + oxide_preempt_cur_ctx], rax",
    "    mov  qword ptr [rip + oxide_preempt_next_ctx], 0",
    "    call oxide_context_switch",
    // -- shared resume label. Both the no-switch path (jz 2f) and
    //    the post-switch path (oxide_context_switch's `ret` land
    //    here on the new task's stack) drop into the epilogue.
    "2:  jmp oxide_irq_resume_user",
    ".size oxide_irq_vec_40, . - oxide_irq_vec_40",

    // ----- shared IRQ epilogue --------------------------------------------
    // Globally addressable so `Context::new_kernel_with_irq_frame`
    // can park its address as the saved-RIP at scaffold base.
    ".globl oxide_irq_resume_user",
    ".type  oxide_irq_resume_user, @function",
    "oxide_irq_resume_user:",
    "    pop r11", "    pop r10", "    pop r9", "    pop r8",
    "    pop rdi", "    pop rsi",
    "    pop rdx", "    pop rcx", "    pop rax",
    "    add rsp, 16",              // drop our vec + err
    "    iretq",
    ".size oxide_irq_resume_user, . - oxide_irq_resume_user",
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_irq_vec_40();
    fn oxide_irq_resume_user() -> !;
}

/// Address of the IRQ stub for `vec`, or `0` if no IRQ stub is
/// registered for that vector (caller falls back to fault stub).
/// # C: O(1)
pub fn irq_stub_addr(vec: u8) -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        if vec == 0x40 {
            return oxide_irq_vec_40 as usize as u64;
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = vec; }
    0
}

/// Address of the shared IRQ epilogue (`oxide_irq_resume_user`),
/// the saved-RIP value `Context::new_kernel_with_irq_frame` parks
/// at scaffold base. Returns 0 on host (asm symbol absent).
/// # C: O(1)
pub fn irq_resume_user_addr() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { oxide_irq_resume_user as usize as u64 }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}
