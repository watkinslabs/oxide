// aarch64 EL1 vector table install per `22§5`.
//
// VMSAv8 mandates a 16-entry table at `VBAR_EL1`; each entry is
// 0x80 bytes. Layout per ARM ARM D1.10 Tab. D1-7:
//   0x000 Sync           current EL with SP_EL0
//   0x080 IRQ            current EL with SP_EL0
//   0x100 FIQ            current EL with SP_EL0
//   0x180 SError         current EL with SP_EL0
//   0x200 Sync           current EL with SP_ELx
//   0x280 IRQ            current EL with SP_ELx
//   0x300 FIQ            current EL with SP_ELx
//   0x380 SError         current EL with SP_ELx
//   0x400 Sync           lower EL using AArch64
//   0x480 IRQ            lower EL using AArch64
//   0x500 FIQ            lower EL using AArch64
//   0x580 SError         lower EL using AArch64
//   0x600 Sync           lower EL using AArch32
//   0x680 IRQ            lower EL using AArch32
//   0x700 FIQ            lower EL using AArch32
//   0x780 SError         lower EL using AArch32
//
// v1 lands the data path: a default-vector handler that prints
// (ESR/FAR/ELR) + halts for unexpected synchronous/SError/FIQ paths,
// and an IRQ handler at slot 0x280 ("Current EL with SP_ELx, IRQ")
// that saves caller-save GP regs, calls a Rust dispatcher, and
// `eret`s. Per-cause sync dispatch (`ESR.EC` decode → SVC syscall /
// IABT/DABT page fault) rides alongside scheduler bring-up.

/// Vector table is exactly 16 × 0x80 = 0x800 bytes per ARM ARM.
pub const VECTOR_TABLE_SIZE: usize = 0x800;

/// Per-entry stride.
pub const VECTOR_ENTRY_BYTES: usize = 0x80;

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text",
    ".balign 0x800",
    ".globl oxide_vector_table",
    ".type  oxide_vector_table, %function",
    "oxide_vector_table:",
    // 16 entries; each pads to 0x80 bytes via `.balign` after the
    // `b` insn so the next slot lands on the right offset.
    // 0x000: Sync, current EL with SP_EL0
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    // 0x080: IRQ, current EL with SP_EL0
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    // 0x100: FIQ, current EL with SP_EL0
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    // 0x180: SError, current EL with SP_EL0
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    // 0x200: Sync, current EL with SP_ELx
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    // 0x280: IRQ, current EL with SP_ELx — kernel-mode IRQs land here.
    "    b oxide_irq_vector_handler",
    "    .balign 0x80",
    // 0x300: FIQ, current EL with SP_ELx
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    // 0x380: SError, current EL with SP_ELx
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    ".size oxide_vector_table, . - oxide_vector_table",

    ".balign 4",
    ".globl oxide_default_vector_handler",
    ".type  oxide_default_vector_handler, %function",
    "oxide_default_vector_handler:",
    "    msr daifset, #0xf",   // mask D, A, I, F
    // Reserve a 16-aligned scratch area on the stack for the printer
    // call frame. Prepare ELR_EL1, ESR_EL1, FAR_EL1 in arg regs and
    // tail-call into the Rust printer; halt on return.
    "    sub  sp, sp, #16",
    "    mrs  x0, esr_el1",
    "    mrs  x1, far_el1",
    "    mrs  x2, elr_el1",
    "    bl   oxide_fault_print_rust",
    "1:  wfi",
    "    b 1b",
    ".size oxide_default_vector_handler, . - oxide_default_vector_handler",

    // IRQ entry per `22§5` + `14§R07`. Frame = 192 B = 22 × 8 GP +
    // ELR_EL1 + SPSR_EL1. The ELR/SPSR pair was missing pre-R07; an
    // `eret` after a context switch would have eret'd into whatever
    // ELR/SPSR currently held — wrong as soon as the dispatcher
    // swapped tasks. They sit at [sp+0xb0..0xc0] now.
    //
    // After the dispatcher returns, the asm reads
    // `oxide_preempt_next_ctx`. If non-null, calls
    // `oxide_context_switch(cur, next)`; the `ret` lands either at
    // the `1:` label below (no-switch / fall-through) or at
    // `oxide_irq_resume_user` on the new task's stack (the new
    // task's `Context.lr` is set to that address by
    // `Context::new_kernel_with_irq_frame` or by a prior preemption).
    ".balign 4",
    ".globl oxide_irq_vector_handler",
    ".type  oxide_irq_vector_handler, %function",
    "oxide_irq_vector_handler:",
    "    sub  sp, sp, #192",
    "    stp  x0,  x1,  [sp, #0]",
    "    stp  x2,  x3,  [sp, #16]",
    "    stp  x4,  x5,  [sp, #32]",
    "    stp  x6,  x7,  [sp, #48]",
    "    stp  x8,  x9,  [sp, #64]",
    "    stp  x10, x11, [sp, #80]",
    "    stp  x12, x13, [sp, #96]",
    "    stp  x14, x15, [sp, #112]",
    "    stp  x16, x17, [sp, #128]",
    "    stp  x18, x29, [sp, #144]",
    "    stp  x30, xzr, [sp, #160]",
    "    mrs  x9,  elr_el1",
    "    mrs  x10, spsr_el1",
    "    stp  x9,  x10, [sp, #176]",
    "    bl   oxide_arm_irq_dispatch",
    // -- schedule-on-exit per `14§R07`. Rust dispatcher writes
    //    `oxide_preempt_next_ctx` if a switch is wanted; null = stay.
    "    adrp x9,  oxide_preempt_next_ctx",
    "    add  x9,  x9, :lo12:oxide_preempt_next_ctx",
    "    ldr  x10, [x9]",
    "    cbz  x10, 1f",
    "    adrp x11, oxide_preempt_cur_ctx",
    "    add  x11, x11, :lo12:oxide_preempt_cur_ctx",
    "    ldr  x0,  [x11]",
    "    mov  x1,  x10",
    "    str  x10, [x11]",                 // CUR := NEXT (commit)
    "    str  xzr, [x9]",                  // clear NEXT slot
    "    bl   oxide_context_switch",
    "    b    oxide_irq_resume_user",      // shared epilogue
    "1:  b    oxide_irq_resume_user",
    ".size oxide_irq_vector_handler, . - oxide_irq_vector_handler",

    // Shared IRQ epilogue. Address parked as `Context.lr` on every
    // task that may be entered via the IRQ tail (per
    // `Context::new_kernel_with_irq_frame`).
    ".balign 4",
    ".globl oxide_irq_resume_user",
    ".type  oxide_irq_resume_user, %function",
    "oxide_irq_resume_user:",
    "    ldp  x9,  x10, [sp, #176]",
    "    msr  elr_el1,  x9",
    "    msr  spsr_el1, x10",
    "    ldp  x30, xzr, [sp, #160]",
    "    ldp  x18, x29, [sp, #144]",
    "    ldp  x16, x17, [sp, #128]",
    "    ldp  x14, x15, [sp, #112]",
    "    ldp  x12, x13, [sp, #96]",
    "    ldp  x10, x11, [sp, #80]",
    "    ldp  x8,  x9,  [sp, #64]",
    "    ldp  x6,  x7,  [sp, #48]",
    "    ldp  x4,  x5,  [sp, #32]",
    "    ldp  x2,  x3,  [sp, #16]",
    "    ldp  x0,  x1,  [sp, #0]",
    "    add  sp, sp, #192",
    "    eret",
    ".size oxide_irq_resume_user, . - oxide_irq_resume_user",
);

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_irq_resume_user() -> !;
}

/// Address of the shared IRQ epilogue (`oxide_irq_resume_user`),
/// the saved-LR value `Context::new_kernel_with_irq_frame` parks
/// in `Context.lr`. Returns 0 on host (asm symbol absent).
/// # C: O(1)
pub fn irq_resume_user_addr() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { oxide_irq_resume_user as usize as u64 }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
extern "C" {
    static oxide_vector_table: u8;
}

/// Address of the vector table, or 0 on host where the asm symbol
/// doesn't exist.
fn vector_table_addr() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: taking the address of a `&'static` extern symbol;
        // no read of the bytes themselves at this site.
        unsafe { &oxide_vector_table as *const u8 as u64 }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Install the default vector table by writing `VBAR_EL1`. Single-
/// shot at boot.
///
/// # SAFETY: caller is the boot path; runs single-CPU with IRQs
/// masked. The table is stored in `.text` and is read-only from
/// kernel code; the CPU dereferences entries asynchronously on every
/// exception.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn install_default() {
    let base = vector_table_addr();
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `msr vbar_el1` is privileged at EL1; sets the
        // vector base. ARM ARM D13.2.111. `isb` ensures subsequent
        // exceptions vector to the new table.
        unsafe {
            core::arch::asm!(
                "msr vbar_el1, {b}",
                "isb",
                b = in(reg) base,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    let _ = base;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_table_size_matches_arm_arm() {
        // ARM ARM D1.10: 16 entries × 0x80 bytes = 0x800.
        assert_eq!(VECTOR_TABLE_SIZE, 0x800);
        assert_eq!(VECTOR_ENTRY_BYTES, 0x80);
        assert_eq!(VECTOR_ENTRY_BYTES * 16, VECTOR_TABLE_SIZE);
    }

    #[test]
    fn install_default_compiles_on_host() {
        // SAFETY: hosted test; the asm path is cfg'd out, so install
        // exercises only the no-op fallback branch.
        unsafe { install_default() };
    }
}
