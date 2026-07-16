// Per-vector IRQ entry stubs per `22§4` + IRQ-exit preemption epilogue
// per `14§R07`.
//
// Distinct from the fault stubs (`fault.rs`): IRQ stubs save the
// scratch registers, call the Rust dispatcher, then call
// `oxide_irq_resched_on_exit` (one engine — it calls the single
// `schedule()` iff returning to user with a pending resched), then
// `iretq` back to whatever task we end up resuming. The dispatcher
// does the EOI dance; there is no IRQ-tail staging / second switch.
//
// The IRQ epilogue (pop scratch + drop synthetic vec/err + iretq)
// is factored into a dedicated symbol `oxide_irq_resume_user`. A
// freshly-built task (`Context::new_*_with_irq_frame`) stores
// `oxide_finish_switch_tramp` as the saved-RIP at the bottom of the
// scaffold so `oxide_context_switch`'s `ret` pays the
// `finish_task_switch` handoff, then drops into this epilogue.
//
// Phase-1 scope: a single timer vector (0x40). Wider IRQ table
// rides alongside scheduler bring-up.

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
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
    // -- resched-on-exit (`14§R07` / smp-arch.md Phase A). One engine:
    //    pass the interrupted frame's saved CS to the Rust slow path,
    //    which calls the single `schedule()` iff returning to user with a
    //    pending resched. No IRQ-tail staging / second switch engine.
    "    mov  rdi, [rsp + 0x60]",   // saved CS from the iretq frame
    "    call oxide_irq_resched_on_exit",
    "    jmp  oxide_irq_resume_user",
    ".size oxide_irq_vec_40, . - oxide_irq_vec_40",

    // ----- vec 0x41 -- cross-CPU resched IPI per `13§9`. Same shape
    //       as the timer stub; oxide_irq_dispatch differentiates by
    //       reading the saved vec tag. -----------------------------
    ".globl oxide_irq_vec_41",
    ".type  oxide_irq_vec_41, @function",
    "oxide_irq_vec_41:",
    "    push 0",
    "    push 0x41",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld",
    "    mov rdi, rsp",
    "    call oxide_irq_dispatch",
    "    mov  rdi, [rsp + 0x60]",   // saved CS from the iretq frame
    "    call oxide_irq_resched_on_exit",
    "    jmp  oxide_irq_resume_user",
    ".size oxide_irq_vec_41, . - oxide_irq_vec_41",

    // ----- vec 0x42 -- cross-CPU TLB shootdown IPI per `20§5`. Same
    //       shape as the resched stub; oxide_irq_dispatch routes the
    //       0x42 tag to the TLB-shootdown service (local invlpg + ACK).
    ".globl oxide_irq_vec_42",
    ".type  oxide_irq_vec_42, @function",
    "oxide_irq_vec_42:",
    "    push 0",
    "    push 0x42",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld",
    "    mov rdi, rsp",
    "    call oxide_irq_dispatch",
    "    mov  rdi, [rsp + 0x60]",   // saved CS from the iretq frame
    "    call oxide_irq_resched_on_exit",
    "    jmp  oxide_irq_resume_user",
    ".size oxide_irq_vec_42, . - oxide_irq_vec_42",

    // ----- vec 0x50 -- MSI vector (F57). Same shape as the timer
    //       stub; oxide_irq_dispatch differentiates by reading the
    //       saved vec tag and bumps MSI_FIRES. ----------------------
    ".globl oxide_irq_vec_50",
    ".type  oxide_irq_vec_50, @function",
    "oxide_irq_vec_50:",
    "    push 0",
    "    push 0x50",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld",
    "    mov rdi, rsp",
    "    call oxide_irq_dispatch",
    "    mov  rdi, [rsp + 0x60]",   // saved CS from the iretq frame
    "    call oxide_irq_resched_on_exit",
    "    jmp  oxide_irq_resume_user",
    ".size oxide_irq_vec_50, . - oxide_irq_vec_50",

    // ----- vec 0x51..0x57 -- MSI pool (F58). Same shape as 0x50.
    //       arch-irq's per-vector handler table looks up by the
    //       pushed vec tag, calls the registered driver fn, then
    //       falls through to the standard tail. ------------------
    ".globl oxide_irq_vec_51",
    ".type  oxide_irq_vec_51, @function",
    "oxide_irq_vec_51:",
    "    push 0", "    push 0x51",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld", "    mov rdi, rsp", "    call oxide_irq_dispatch",
    "    mov  rdi, [rsp + 0x60]",   // saved CS from the iretq frame
    "    call oxide_irq_resched_on_exit",
    "    jmp  oxide_irq_resume_user",
    ".size oxide_irq_vec_51, . - oxide_irq_vec_51",

    ".globl oxide_irq_vec_52",
    ".type  oxide_irq_vec_52, @function",
    "oxide_irq_vec_52:",
    "    push 0", "    push 0x52",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld", "    mov rdi, rsp", "    call oxide_irq_dispatch",
    "    mov  rdi, [rsp + 0x60]",   // saved CS from the iretq frame
    "    call oxide_irq_resched_on_exit",
    "    jmp  oxide_irq_resume_user",
    ".size oxide_irq_vec_52, . - oxide_irq_vec_52",

    ".globl oxide_irq_vec_53",
    ".type  oxide_irq_vec_53, @function",
    "oxide_irq_vec_53:",
    "    push 0", "    push 0x53",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld", "    mov rdi, rsp", "    call oxide_irq_dispatch",
    "    mov  rdi, [rsp + 0x60]",   // saved CS from the iretq frame
    "    call oxide_irq_resched_on_exit",
    "    jmp  oxide_irq_resume_user",
    ".size oxide_irq_vec_53, . - oxide_irq_vec_53",

    ".globl oxide_irq_vec_54",
    ".type  oxide_irq_vec_54, @function",
    "oxide_irq_vec_54:",
    "    push 0", "    push 0x54",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld", "    mov rdi, rsp", "    call oxide_irq_dispatch",
    "    mov  rdi, [rsp + 0x60]",   // saved CS from the iretq frame
    "    call oxide_irq_resched_on_exit",
    "    jmp  oxide_irq_resume_user",
    ".size oxide_irq_vec_54, . - oxide_irq_vec_54",

    ".globl oxide_irq_vec_55",
    ".type  oxide_irq_vec_55, @function",
    "oxide_irq_vec_55:",
    "    push 0", "    push 0x55",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld", "    mov rdi, rsp", "    call oxide_irq_dispatch",
    "    mov  rdi, [rsp + 0x60]",   // saved CS from the iretq frame
    "    call oxide_irq_resched_on_exit",
    "    jmp  oxide_irq_resume_user",
    ".size oxide_irq_vec_55, . - oxide_irq_vec_55",

    ".globl oxide_irq_vec_56",
    ".type  oxide_irq_vec_56, @function",
    "oxide_irq_vec_56:",
    "    push 0", "    push 0x56",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld", "    mov rdi, rsp", "    call oxide_irq_dispatch",
    "    mov  rdi, [rsp + 0x60]",   // saved CS from the iretq frame
    "    call oxide_irq_resched_on_exit",
    "    jmp  oxide_irq_resume_user",
    ".size oxide_irq_vec_56, . - oxide_irq_vec_56",

    ".globl oxide_irq_vec_57",
    ".type  oxide_irq_vec_57, @function",
    "oxide_irq_vec_57:",
    "    push 0", "    push 0x57",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld", "    mov rdi, rsp", "    call oxide_irq_dispatch",
    "    mov  rdi, [rsp + 0x60]",   // saved CS from the iretq frame
    "    call oxide_irq_resched_on_exit",
    "    jmp  oxide_irq_resume_user",
    ".size oxide_irq_vec_57, . - oxide_irq_vec_57",

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
    fn oxide_irq_vec_41();
    fn oxide_irq_vec_42();
    fn oxide_irq_vec_50();
    fn oxide_irq_vec_51();
    fn oxide_irq_vec_52();
    fn oxide_irq_vec_53();
    fn oxide_irq_vec_54();
    fn oxide_irq_vec_55();
    fn oxide_irq_vec_56();
    fn oxide_irq_vec_57();
    fn oxide_irq_resume_user() -> !;
}

/// LAPIC timer vector (`22§4`).
pub const VEC_TIMER:   u8 = 0x40;
/// Cross-CPU resched IPI vector per `13§9`.
pub const VEC_RESCHED: u8 = 0x41;
/// Cross-CPU TLB-shootdown IPI vector per `20§5`. The sender (a CPU that
/// downgraded/removed a user PTE) IPIs every other online CPU; each
/// invalidates the target VA locally and ACKs. x86 has no hardware TLB
/// broadcast, unlike aarch64's `tlbi vae1is`.
pub const VEC_TLB_SHOOTDOWN: u8 = 0x42;
/// MSI delivery vector (F57). Legacy alias for the first slot in
/// the per-vector pool. Kept so existing callers compile; new code
/// should call `alloc_x86_vector` and use the returned vector.
pub const VEC_MSI_0: u8 = 0x50;
pub const VEC_MSI_1: u8 = 0x51;
pub const VEC_MSI_2: u8 = 0x52;
pub const VEC_MSI_3: u8 = 0x53;
pub const VEC_MSI_4: u8 = 0x54;
pub const VEC_MSI_5: u8 = 0x55;
pub const VEC_MSI_6: u8 = 0x56;
pub const VEC_MSI_7: u8 = 0x57;
pub const VEC_MSI: u8 = VEC_MSI_0;

/// First / last vector in the per-vector MSI pool (F58). Each
/// device's MSI-X table entry gets a distinct vector in this range;
/// the arch-irq dispatcher routes each vector to its registered
/// handler via the per-vector table.
pub const VEC_MSI_POOL_FIRST: u8 = VEC_MSI_0;
pub const VEC_MSI_POOL_LAST:  u8 = VEC_MSI_7;
pub const VEC_MSI_POOL_LEN: usize =
    (VEC_MSI_POOL_LAST as usize) - (VEC_MSI_POOL_FIRST as usize) + 1;

/// Address of the IRQ stub for `vec`, or `0` if no IRQ stub is
/// registered for that vector (caller falls back to fault stub).
/// # C: O(1)
pub fn irq_stub_addr(vec: u8) -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        match vec {
            VEC_TIMER   => return oxide_irq_vec_40 as *const () as usize as u64,
            VEC_RESCHED => return oxide_irq_vec_41 as *const () as usize as u64,
            VEC_TLB_SHOOTDOWN => return oxide_irq_vec_42 as *const () as usize as u64,
            VEC_MSI_0 => return oxide_irq_vec_50 as *const () as usize as u64,
            VEC_MSI_1 => return oxide_irq_vec_51 as *const () as usize as u64,
            VEC_MSI_2 => return oxide_irq_vec_52 as *const () as usize as u64,
            VEC_MSI_3 => return oxide_irq_vec_53 as *const () as usize as u64,
            VEC_MSI_4 => return oxide_irq_vec_54 as *const () as usize as u64,
            VEC_MSI_5 => return oxide_irq_vec_55 as *const () as usize as u64,
            VEC_MSI_6 => return oxide_irq_vec_56 as *const () as usize as u64,
            VEC_MSI_7 => return oxide_irq_vec_57 as *const () as usize as u64,
            _ => {}
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
    { oxide_irq_resume_user as *const () as usize as u64 }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}
