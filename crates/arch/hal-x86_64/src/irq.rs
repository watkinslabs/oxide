// Per-vector IRQ entry stubs per `22§4` + IRQ-exit preemption epilogue
// per `14§R07`.
//
// Distinct from the fault stubs (`fault.rs`): IRQ stubs save the
// scratch registers, switch to this CPU's per-CPU hardirq stack (F699),
// call the Rust dispatcher, then call `oxide_irq_resched_on_exit` (one
// engine — it calls the single `schedule()` iff returning to user with a
// pending resched), then `iretq` back to whatever task we end up resuming.
// The dispatcher does the EOI dance; there is no IRQ-tail staging.
//
// The 11 per-vector bodies are collapsed into thin heads (tag err+vec,
// jump to `oxide_irq_common`) + one common path, so the per-CPU
// hardirq-stack switch lives in exactly one place (docs/54 "one low-level
// path"). The switch relocates the handler + `do_softirq` re-entry off the
// interrupted task's (possibly already-deep) kernel stack onto a fresh
// guard-paged 16 KiB stack, so an IRQ taken deep in a kernel call chain
// (ext4→block busy-poll with IRQs enabled) no longer overflows it.
//
// The IRQ epilogue (pop scratch + drop synthetic vec/err + iretq) is a
// dedicated symbol `oxide_irq_resume_user`. A freshly-built task
// (`Context::new_*_with_irq_frame`) stores `oxide_finish_switch_tramp` as
// the saved-RIP at the bottom of the scaffold so `oxide_context_switch`'s
// `ret` pays the `finish_task_switch` handoff, then drops into this epilogue.

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text",

    // ----- per-vector heads: tag (synthetic err, vec), jump to common ------
    ".globl oxide_irq_vec_40", ".type oxide_irq_vec_40, @function",
    "oxide_irq_vec_40:", "    push 0", "    push 0x40", "    jmp oxide_irq_common",
    ".size oxide_irq_vec_40, . - oxide_irq_vec_40",
    ".globl oxide_irq_vec_41", ".type oxide_irq_vec_41, @function",
    "oxide_irq_vec_41:", "    push 0", "    push 0x41", "    jmp oxide_irq_common",
    ".size oxide_irq_vec_41, . - oxide_irq_vec_41",
    ".globl oxide_irq_vec_42", ".type oxide_irq_vec_42, @function",
    "oxide_irq_vec_42:", "    push 0", "    push 0x42", "    jmp oxide_irq_common",
    ".size oxide_irq_vec_42, . - oxide_irq_vec_42",
    ".globl oxide_irq_vec_50", ".type oxide_irq_vec_50, @function",
    "oxide_irq_vec_50:", "    push 0", "    push 0x50", "    jmp oxide_irq_common",
    ".size oxide_irq_vec_50, . - oxide_irq_vec_50",
    ".globl oxide_irq_vec_51", ".type oxide_irq_vec_51, @function",
    "oxide_irq_vec_51:", "    push 0", "    push 0x51", "    jmp oxide_irq_common",
    ".size oxide_irq_vec_51, . - oxide_irq_vec_51",
    ".globl oxide_irq_vec_52", ".type oxide_irq_vec_52, @function",
    "oxide_irq_vec_52:", "    push 0", "    push 0x52", "    jmp oxide_irq_common",
    ".size oxide_irq_vec_52, . - oxide_irq_vec_52",
    ".globl oxide_irq_vec_53", ".type oxide_irq_vec_53, @function",
    "oxide_irq_vec_53:", "    push 0", "    push 0x53", "    jmp oxide_irq_common",
    ".size oxide_irq_vec_53, . - oxide_irq_vec_53",
    ".globl oxide_irq_vec_54", ".type oxide_irq_vec_54, @function",
    "oxide_irq_vec_54:", "    push 0", "    push 0x54", "    jmp oxide_irq_common",
    ".size oxide_irq_vec_54, . - oxide_irq_vec_54",
    ".globl oxide_irq_vec_55", ".type oxide_irq_vec_55, @function",
    "oxide_irq_vec_55:", "    push 0", "    push 0x55", "    jmp oxide_irq_common",
    ".size oxide_irq_vec_55, . - oxide_irq_vec_55",
    ".globl oxide_irq_vec_56", ".type oxide_irq_vec_56, @function",
    "oxide_irq_vec_56:", "    push 0", "    push 0x56", "    jmp oxide_irq_common",
    ".size oxide_irq_vec_56, . - oxide_irq_vec_56",
    ".globl oxide_irq_vec_57", ".type oxide_irq_vec_57, @function",
    "oxide_irq_vec_57:", "    push 0", "    push 0x57", "    jmp oxide_irq_common",
    ".size oxide_irq_vec_57, . - oxide_irq_vec_57",

    // ----- common IRQ path -------------------------------------------------
    // Save scratch, switch to the per-CPU hardirq stack (unless already
    // nested on it), dispatch, unwind back to the interrupted stack, then
    // resched-on-exit + iretq. The interrupted frame (9 scratch + err/vec +
    // CPU iretq image) stays on the OUTER stack; only the dispatcher's own
    // usage + nested IRQs + do_softirq run on the hardirq stack (Linux model).
    ".type oxide_irq_common, @function",
    "oxide_irq_common:",
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    "    cld",
    "    mov  rax, rsp",            // rax = interrupted frame ptr (outer stack)
    "    mov  rdi, rax",            // arg0 = frame ptr (dispatch reads offsets off this)
    // hardirq-stack switch with a STATELESS nesting guard: switch rsp to
    // gs:[24] (this CPU's guard-paged 16 KiB hardirq-stack top) UNLESS the
    // interrupted rsp is already inside that stack (a nested IRQ during the
    // do_softirq sti-window) — resetting rsp then would clobber the outer
    // softirq frame. Range test: (top - outer_rsp) <= 0x4000 ⇒ nested.
    // 0x4000 == sched::kstack::KSTACK_BYTES (reverse-asserted there).
    "    mov  rcx, gs:[24]",        // this CPU's hardirq stack top (0 = unarmed)
    "    test rcx, rcx",
    "    jz   2f",                  // unarmed (early boot) -> stay on current stack
    "    mov  rdx, rcx",
    "    sub  rdx, rax",            // rdx = top - outer_rsp (unsigned)
    "    cmp  rdx, 0x4000",
    "    jbe  2f",                  // outer_rsp within [top-16K, top] -> nested, no reset
    "    mov  rsp, rcx",            // switch to the fresh 16-aligned hardirq-stack top
    "2:",
    "    push rax",                 // save outer rsp
    "    push rax",                 // 16-align pad (rsp is 16-aligned at 2:)
    "    call oxide_irq_dispatch",  // handler + sti/do_softirq/cli on the hardirq stack
    "    pop  rax",                 // drop pad
    "    pop  rsp",                 // back to the interrupted (outer) stack
    // -- resched-on-exit (`14§R07`): pass the interrupted frame's saved CS to
    //    the Rust slow path, which calls schedule() iff returning to user with
    //    a pending resched. Runs on the OUTER stack (correct save point).
    "    mov  rdi, [rsp + 0x60]",   // saved CS from the iretq frame
    "    call oxide_irq_resched_on_exit",
    "    jmp  oxide_irq_resume_user",
    ".size oxide_irq_common, . - oxide_irq_common",

    // ----- shared IRQ epilogue --------------------------------------------
    // Globally addressable so `Context::new_kernel_with_irq_frame`
    // can park its address as the saved-RIP at scaffold base. Reached with
    // rsp already restored to the interrupted (outer) stack.
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

/// Per-CPU slot (`gs:[24]`) holding this CPU's hardirq-stack top; 0 = unarmed.
/// Coupled to the `mov rcx, gs:[24]` literal in `oxide_irq_common` above.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const PERCPU_HARDIRQ_STACK_OFF: usize = 24;

/// Arm THIS CPU's hardirq stack. `top` is the 16-aligned high end of a
/// guard-paged 16 KiB stack (from `sched::kstack::alloc().top()`, leaked).
/// Call after `set_percpu_base` (gs valid) and BEFORE this CPU's first `sti`.
/// While unarmed (`gs:[24]==0`) the switch is skipped and IRQs run on the
/// current stack — safe, since nothing deep runs IRQs-on before arming.
/// # SAFETY: gs points at this CPU's per-CPU area; `top` outlives the kernel.
/// # C: O(1)
pub unsafe fn init_percpu_hardirq_stack(top: u64) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    // SAFETY: gs base = this CPU's per-CPU page; slot 24 is reserved for this.
    unsafe {
        core::arch::asm!(
            "mov gs:[{off}], {v}",
            off = const PERCPU_HARDIRQ_STACK_OFF,
            v = in(reg) top,
            options(nostack, preserves_flags),
        );
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = top; }
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
