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
    "    mov  rax, gs:[8]",   // per-CPU NEXT-ctx staging slot
    "    test rax, rax",
    "    jz   2f",
    "    mov  rdi, gs:[16]",  // per-CPU CUR-ctx staging slot (prev)
    "    mov  rsi, rax",
    "    mov  gs:[16], rax",  // CUR := NEXT (commit)
    "    mov  qword ptr gs:[8], 0",  // clear NEXT slot
    "    call oxide_context_switch",
    // -- shared resume label. Both the no-switch path (jz 2f) and
    //    the post-switch path (oxide_context_switch's `ret` land
    //    here on the new task's stack) drop into the epilogue.
    "2:  jmp oxide_irq_resume_user",
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
    "    mov  rax, gs:[8]",   // per-CPU NEXT-ctx staging slot
    "    test rax, rax",
    "    jz   3f",
    "    mov  rdi, gs:[16]",  // per-CPU CUR-ctx staging slot (prev)
    "    mov  rsi, rax",
    "    mov  gs:[16], rax",  // CUR := NEXT (commit)
    "    mov  qword ptr gs:[8], 0",  // clear NEXT slot
    "    call oxide_context_switch",
    "3:  jmp oxide_irq_resume_user",
    ".size oxide_irq_vec_41, . - oxide_irq_vec_41",

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
    "    mov  rax, gs:[8]",   // per-CPU NEXT-ctx staging slot
    "    test rax, rax",
    "    jz   4f",
    "    mov  rdi, gs:[16]",  // per-CPU CUR-ctx staging slot (prev)
    "    mov  rsi, rax",
    "    mov  gs:[16], rax",  // CUR := NEXT (commit)
    "    mov  qword ptr gs:[8], 0",  // clear NEXT slot
    "    call oxide_context_switch",
    "4:  jmp oxide_irq_resume_user",
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
    "    mov  rax, gs:[8]",   // per-CPU NEXT-ctx staging slot
    "    test rax, rax", "    jz 51f",
    "    mov  rdi, gs:[16]",  // per-CPU CUR-ctx staging slot (prev)
    "    mov  rsi, rax",
    "    mov  gs:[16], rax",  // CUR := NEXT (commit)
    "    mov  qword ptr gs:[8], 0",  // clear NEXT slot
    "    call oxide_context_switch",
    "51: jmp oxide_irq_resume_user",
    ".size oxide_irq_vec_51, . - oxide_irq_vec_51",

    ".globl oxide_irq_vec_52",
    ".type  oxide_irq_vec_52, @function",
    "oxide_irq_vec_52:",
    "    push 0", "    push 0x52",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld", "    mov rdi, rsp", "    call oxide_irq_dispatch",
    "    mov  rax, gs:[8]",   // per-CPU NEXT-ctx staging slot
    "    test rax, rax", "    jz 52f",
    "    mov  rdi, gs:[16]",  // per-CPU CUR-ctx staging slot (prev)
    "    mov  rsi, rax",
    "    mov  gs:[16], rax",  // CUR := NEXT (commit)
    "    mov  qword ptr gs:[8], 0",  // clear NEXT slot
    "    call oxide_context_switch",
    "52: jmp oxide_irq_resume_user",
    ".size oxide_irq_vec_52, . - oxide_irq_vec_52",

    ".globl oxide_irq_vec_53",
    ".type  oxide_irq_vec_53, @function",
    "oxide_irq_vec_53:",
    "    push 0", "    push 0x53",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld", "    mov rdi, rsp", "    call oxide_irq_dispatch",
    "    mov  rax, gs:[8]",   // per-CPU NEXT-ctx staging slot
    "    test rax, rax", "    jz 53f",
    "    mov  rdi, gs:[16]",  // per-CPU CUR-ctx staging slot (prev)
    "    mov  rsi, rax",
    "    mov  gs:[16], rax",  // CUR := NEXT (commit)
    "    mov  qword ptr gs:[8], 0",  // clear NEXT slot
    "    call oxide_context_switch",
    "53: jmp oxide_irq_resume_user",
    ".size oxide_irq_vec_53, . - oxide_irq_vec_53",

    ".globl oxide_irq_vec_54",
    ".type  oxide_irq_vec_54, @function",
    "oxide_irq_vec_54:",
    "    push 0", "    push 0x54",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld", "    mov rdi, rsp", "    call oxide_irq_dispatch",
    "    mov  rax, gs:[8]",   // per-CPU NEXT-ctx staging slot
    "    test rax, rax", "    jz 54f",
    "    mov  rdi, gs:[16]",  // per-CPU CUR-ctx staging slot (prev)
    "    mov  rsi, rax",
    "    mov  gs:[16], rax",  // CUR := NEXT (commit)
    "    mov  qword ptr gs:[8], 0",  // clear NEXT slot
    "    call oxide_context_switch",
    "54: jmp oxide_irq_resume_user",
    ".size oxide_irq_vec_54, . - oxide_irq_vec_54",

    ".globl oxide_irq_vec_55",
    ".type  oxide_irq_vec_55, @function",
    "oxide_irq_vec_55:",
    "    push 0", "    push 0x55",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld", "    mov rdi, rsp", "    call oxide_irq_dispatch",
    "    mov  rax, gs:[8]",   // per-CPU NEXT-ctx staging slot
    "    test rax, rax", "    jz 55f",
    "    mov  rdi, gs:[16]",  // per-CPU CUR-ctx staging slot (prev)
    "    mov  rsi, rax",
    "    mov  gs:[16], rax",  // CUR := NEXT (commit)
    "    mov  qword ptr gs:[8], 0",  // clear NEXT slot
    "    call oxide_context_switch",
    "55: jmp oxide_irq_resume_user",
    ".size oxide_irq_vec_55, . - oxide_irq_vec_55",

    ".globl oxide_irq_vec_56",
    ".type  oxide_irq_vec_56, @function",
    "oxide_irq_vec_56:",
    "    push 0", "    push 0x56",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld", "    mov rdi, rsp", "    call oxide_irq_dispatch",
    "    mov  rax, gs:[8]",   // per-CPU NEXT-ctx staging slot
    "    test rax, rax", "    jz 56f",
    "    mov  rdi, gs:[16]",  // per-CPU CUR-ctx staging slot (prev)
    "    mov  rsi, rax",
    "    mov  gs:[16], rax",  // CUR := NEXT (commit)
    "    mov  qword ptr gs:[8], 0",  // clear NEXT slot
    "    call oxide_context_switch",
    "56: jmp oxide_irq_resume_user",
    ".size oxide_irq_vec_56, . - oxide_irq_vec_56",

    ".globl oxide_irq_vec_57",
    ".type  oxide_irq_vec_57, @function",
    "oxide_irq_vec_57:",
    "    push 0", "    push 0x57",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld", "    mov rdi, rsp", "    call oxide_irq_dispatch",
    "    mov  rax, gs:[8]",   // per-CPU NEXT-ctx staging slot
    "    test rax, rax", "    jz 57f",
    "    mov  rdi, gs:[16]",  // per-CPU CUR-ctx staging slot (prev)
    "    mov  rsi, rax",
    "    mov  gs:[16], rax",  // CUR := NEXT (commit)
    "    mov  qword ptr gs:[8], 0",  // clear NEXT slot
    "    call oxide_context_switch",
    "57: jmp oxide_irq_resume_user",
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
/// MSI delivery vector (F57). Legacy alias for the first slot in
/// the per-vector pool. Kept so existing callers compile; new code
/// should call `alloc_x86_vector` and use the returned vector.
pub const VEC_MSI:     u8 = 0x50;

/// First / last vector in the per-vector MSI pool (F58). Each
/// device's MSI-X table entry gets a distinct vector in this range;
/// the arch-irq dispatcher routes each vector to its registered
/// handler via the per-vector table.
pub const VEC_MSI_POOL_FIRST: u8 = 0x50;
pub const VEC_MSI_POOL_LAST:  u8 = 0x57;
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
            0x50 => return oxide_irq_vec_50 as *const () as usize as u64,
            0x51 => return oxide_irq_vec_51 as *const () as usize as u64,
            0x52 => return oxide_irq_vec_52 as *const () as usize as u64,
            0x53 => return oxide_irq_vec_53 as *const () as usize as u64,
            0x54 => return oxide_irq_vec_54 as *const () as usize as u64,
            0x55 => return oxide_irq_vec_55 as *const () as usize as u64,
            0x56 => return oxide_irq_vec_56 as *const () as usize as u64,
            0x57 => return oxide_irq_vec_57 as *const () as usize as u64,
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
