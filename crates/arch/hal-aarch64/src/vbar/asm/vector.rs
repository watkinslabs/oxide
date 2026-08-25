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
    // 0x400: Sync from lower EL, AArch64 — SVC syscall + EL0 faults.
    "    b oxide_lower_el_sync_handler",
    "    .balign 0x80",
    // 0x480: IRQ from lower EL, AArch64 — EL0 → EL1 IRQ delivery.
    // Same handler as the kernel-side IRQ slot; the asm vector enters
    // with sp_el0 holding the user stack and the IRQ dispatcher saves
    // it as part of the 288-byte frame. Without this, PL011 RX (SPI
    // 33) and the CNTV timer (INTID 27) silently never deliver while
    // userspace is running — the wedge masquerades as "GIC isn't
    // routing" but is actually our own vector table dropping the IRQ.
    "    b oxide_irq_vector_handler",
    "    .balign 0x80",
    // 0x500: FIQ from lower EL, AArch64
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    // 0x580: SError from lower EL, AArch64
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    // 0x600..0x780: AArch32 vectors — unused (no compat-mode userspace v1).
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    "    b oxide_default_vector_handler",
    "    .balign 0x80",
    ".size oxide_vector_table, . - oxide_vector_table",

);

