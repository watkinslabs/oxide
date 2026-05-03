// Per-vector IRQ entry stubs per `22§4`.
//
// Distinct from the fault stubs (`fault.rs`): IRQ stubs save the
// scratch registers, call a Rust dispatcher, restore, and `iretq`
// back to the interrupted code. The dispatcher does the EOI dance.
//
// Phase-1 scope: a single timer vector (0x40). Wider IRQ table
// rides alongside scheduler bring-up.

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".intel_syntax noprefix",
    ".section .text",
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
    "    pop r11", "    pop r10", "    pop r9", "    pop r8",
    "    pop rdi", "    pop rsi",
    "    pop rdx", "    pop rcx", "    pop rax",
    "    add rsp, 16",              // drop our vec + err
    "    iretq",
    ".size oxide_irq_vec_40, . - oxide_irq_vec_40",
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_irq_vec_40();
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
