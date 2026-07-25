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

    ".balign 4",
    ".globl oxide_default_vector_handler",
    ".type  oxide_default_vector_handler, %function",
    // Linux `kernel_entry` / `kernel_exit` parity for the fault vector
    // (docs/54§1.6): the COMPLETE interrupted state — x0..x30 AND
    // ELR_EL1 / SPSR_EL1 / SP_EL0 — is owned by this exception frame, never
    // left live in registers across the handler call.
    //
    // Both halves of that were missing, and both are only safe while a fault
    // handler can never block. Once the registered handler demand-pages
    // through block I/O and reschedules with IRQs enabled in kernel context
    // (the IRQs-on migration), the handler's context switch runs arbitrary
    // other tasks on this CPU:
    //
    //   * x19..x28 were relied upon via AAPCS across
    //     `oxide_fault_print_rust`, so the faulting kernel code resumed with
    //     a FOREIGN task's callee-saved registers;
    //   * ELR_EL1 / SPSR_EL1 were left in the system registers, so every
    //     other task's exception entry/return overwrote them — and the
    //     handled-path `eret` below then returned to a STALE kernel PC while
    //     restoring this frame's (user) register file. Observed as
    //     virtio-blk `do_request` executing at EL1 with the interrupted
    //     user's x27 == 0 and SP_EL1 == kstack_top: the ARM IRQs-on
    //     "register corruption".
    //
    // Frame: 288 B, layout shared with the SVC / software-step / undef
    // frames so all four have one shape.
    //   [sp+0x00..0x90]  x0..x18 + x29
    //   [sp+0xa0]        x30 (lr) + pad
    //   [sp+0xb0]        ELR_EL1 + SPSR_EL1
    //   [sp+0xc0]        SP_EL0 + pad
    //   [sp+0xd0..0x118] x19..x28
    ".balign 4",
    "oxide_default_vector_handler:",
    "    msr daifset, #0xf",       // mask D, A, I, F
    "    sub  sp, sp, #288",
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
    "    str  x30,      [sp, #160]",
    "    mrs  x9,  elr_el1",
    "    mrs  x10, spsr_el1",
    "    stp  x9,  x10, [sp, #176]",
    "    mrs  x9,  sp_el0",
    "    str  x9,       [sp, #192]",
    "    stp  x19, x20, [sp, #0xd0]",
    "    stp  x21, x22, [sp, #0xe0]",
    "    stp  x23, x24, [sp, #0xf0]",
    "    stp  x25, x26, [sp, #0x100]",
    "    stp  x27, x28, [sp, #0x110]",
    "    mrs  x0,  esr_el1",
    "    mrs  x1,  far_el1",
    "    mrs  x2,  elr_el1",
    // The default handler only returns for a fault that was resolved. Save
    // x30 before using it as an ABI argument; the handled path restores every
    // user register from this frame before eret (docs/54§1.6).
    "    ldr  x3,  [sp, #160]",
    "    mrs  x4,  sp_el0",
    "    mov  x5,  x8",
    "    mov  x6,  x26",
    // 8th arg = this frame's base. A handler that redirects the post-eret PC
    // (the exception-table fixup) patches the frame's ELR slot, since the
    // `kernel_exit` restore below would discard a live-register write.
    "    mov  x7,  sp",
    "    bl   oxide_fault_print_rust",
    "    cbz  w0, 1f",             // not handled → wfi forever
    // `kernel_exit`: this exception's ELR/SPSR/SP_EL0 come back from the
    // frame, not from whatever the system registers hold now.
    "    ldp  x9,  x10, [sp, #176]",
    "    msr  elr_el1,  x9",
    "    msr  spsr_el1, x10",
    "    ldr  x9,       [sp, #192]",
    "    msr  sp_el0,   x9",
    "    ldp  x19, x20, [sp, #0xd0]",
    "    ldp  x21, x22, [sp, #0xe0]",
    "    ldp  x23, x24, [sp, #0xf0]",
    "    ldp  x25, x26, [sp, #0x100]",
    "    ldp  x27, x28, [sp, #0x110]",
    "    ldr  x30,      [sp, #160]",
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
    "    add  sp, sp, #288",
    "    eret",                    // handled → retry with regs intact
    "1:  wfi",
    "    b 1b",
    ".size oxide_default_vector_handler, . - oxide_default_vector_handler",

    // -------- Lower-EL sync vector (VBAR_EL1+0x400) ----------------
    // Forks on ESR.EC: 0x15 = SVC AArch64 → syscall path; anything
    // else (BRK, data-abort, instr-abort, ...) falls through to the
    // default vector handler which logs ESR/FAR/ELR and halts (or
    // eret-retries if a registered fault handler returned true).
    //
    // Linux SVC ABI: x8 = nr, x0..x5 = args, x0 = retval.
    // We shuffle to Rust SysV (x0=nr, x1..x5=a0..a4) for the
    // dispatch call. a5 is dropped (no v1 syscall takes 6 args).
    //
    // Frame: 288 B (saved GP set + ELR/SPSR + SP_EL0 + retval slot).
    //   [sp+0x00] x0..x1
    //   [sp+0x10] x2..x3
    //   [sp+0x20] x4..x5
    //   [sp+0x30] x6..x7
    //   [sp+0x40] x8..x9
    //   [sp+0x50] x10..x11
    //   [sp+0x60] x12..x13
    //   [sp+0x70] x14..x15
    //   [sp+0x80] x16..x17
    //   [sp+0x90] x18..x29
    //   [sp+0xa0] x30 + pad
    //   [sp+0xb0] elr_el1 + spsr_el1
    //   [sp+0xc0] sp_el0
    //   [sp+0xc8] retval (set after dispatch)
    ".balign 4",
    ".globl oxide_lower_el_sync_handler",
    ".type  oxide_lower_el_sync_handler, %function",
    "oxide_lower_el_sync_handler:",
    "    msr daifset, #0xf",
    // F204: stash the user's x9 in a tiny 16-byte stack preamble
    // before clobbering it with the EC dispatch. TPIDR_EL1 is
    // already used as the per-CPU base pointer per `21§7`, so we
    // can't use it. Each downstream block (svc/softstep/default)
    // pops the preamble and restores x9 before saving x0..x18 to
    // its own frame. Without this, a demand-page fault on e.g.
    // `ldr w3, [x9, x1]` would resolve and `eret`, but x9 had
    // been clobbered to 0x24 (the data-abort EC code) → retried
    // load uses 0x24 as base and re-faults at far=0x24. Surfaced
    // by dropbear-aarch64 sha256_compress under SSH (F204).
    "    sub sp, sp, #16",
    "    str x9, [sp]",
    "    mrs x9, esr_el1",
    "    lsr x9, x9, #26",
    "    and x9, x9, #0x3f",
    "    cmp x9, #0x15",
    "    b.eq oxide_svc_save_block",
    // F51: EC=0x32 = Software-Step exception from a lower EL.
    // Per ARM ARM D1.16. Saved frame format identical to SVC; the
    // post-save dispatch differs (Rust hook posts SIGTRAP + clears
    // SS bits instead of running the syscall dispatcher).
    "    cmp x9, #0x32",
    "    b.eq oxide_softstep_save_block",
    // EC=0x00 = "Unknown reason" from a lower EL = undefined instruction
    // at EL0. Linux delivers a catchable SIGILL; route to the undef save
    // block (full frame save → Rust hook builds the SIGILL handler frame).
    "    cmp x9, #0",
    "    b.eq oxide_undef_save_block",
    // EC=0x18 = trapped MSR/MRS/system instruction from EL0. Linux permits
    // userspace generic-counter reads; emulate those if firmware still traps,
    // and route every unsupported trapped sysreg to the SIGILL path.
    "    cmp x9, #0x18",
    "    b.eq oxide_sysreg_save_block",
    "    ldr x9, [sp]",
    "    add sp, sp, #16",
    "    b oxide_default_vector_handler",
    "oxide_svc_save_block:",
    "    ldr  x9, [sp]",             // F204: pop 16-B preamble, restore user x9
    "    add  sp, sp, #16",
    "    sub  sp, sp, #288",
    "    stp  x0,  x1,  [sp, #0x00]",
    "    stp  x2,  x3,  [sp, #0x10]",
    "    stp  x4,  x5,  [sp, #0x20]",
    "    stp  x6,  x7,  [sp, #0x30]",
    "    stp  x8,  x9,  [sp, #0x40]",
    "    stp  x10, x11, [sp, #0x50]",
    "    stp  x12, x13, [sp, #0x60]",
    "    stp  x14, x15, [sp, #0x70]",
    "    stp  x16, x17, [sp, #0x80]",
    "    stp  x18, x29, [sp, #0x90]",
    "    str  x30,      [sp, #0xa0]",
    "    mrs  x9,  elr_el1",
    "    mrs  x10, spsr_el1",
    "    stp  x9,  x10, [sp, #0xb0]",
    "    mrs  x9,  sp_el0",
    "    str  x9,       [sp, #0xc0]",
    // Save callee-saved x19..x28 too so a forked child can inherit
    // them. AAPCS64 callee-saved means the kernel C dispatch path
    // would otherwise spill them to its own stack and restore on
    // return — fine for the syscall semantics but invisible to
    // sys_clone, which needs the parent's user x19..x28 to populate
    // the child's resume Context.
    "    stp  x19, x20, [sp, #0xd0]",
    "    stp  x21, x22, [sp, #0xe0]",
    "    stp  x23, x24, [sp, #0xf0]",
    "    stp  x25, x26, [sp, #0x100]",
    "    stp  x27, x28, [sp, #0x110]",
    // Stash sp (= base of saved SVC frame) into the global so the
    // dispatcher can locate the saved ELR_EL1 / SP_EL0 / x0 slots
    // for syscalls that need to redirect the post-eret state
    // (sys_execve overwrites ELR_EL1 + SP_EL0 to land at the new
    //  program; sys_fork copies parent regs into the child frame).
    // Per-CPU SVC-frame base: store SP into THIS CPU's per-CPU area
    // (TPIDR_EL1 + 24), not a shared global — two CPUs in `svc` at once
    // must not clobber each other's frame pointer (SP_EL0 poison on the
    // wrong-frame restore). Slot @24: cpu_id@0, preempt_next@8, cur@16.
    "    mrs  x9, tpidr_el1",
    "    mov  x10, sp",
    "    str  x10, [x9, #24]",
    // Shuffle Linux SVC args (x8=nr, x0..x4=a0..a4) into Rust SysV
    // (x0=nr, x1..x5=a0..a4). Bottom-up so we don't clobber sources.
    "    mov  x5, x4",
    "    mov  x4, x3",
    "    mov  x3, x2",
    "    mov  x2, x1",
    "    mov  x1, x0",
    "    mov  x0, x8",
    "    bl   oxide_syscall_dispatch",
    "    str  x0,       [sp, #0xc8]",
    "    b    oxide_lower_sync_restore",
    // F51: Software-Step path. Save block is the SVC's, copied;
    // post-save we call the Rust hook with frame_ptr and let it
    // (a) clear SPSR.SS in the saved SPSR slot, (b) clear MDSCR.SS
    // kernel-side, (c) post SIGTRAP + clear Task.singlestep on the
    // current task. Hook returns the original user x0 so the shared
    // restore block's `ldr x0, [sp, #0xc8]` is a no-op for this path.
    "oxide_softstep_save_block:",
    "    ldr  x9, [sp]",             // F204: pop 16-B preamble, restore user x9
    "    add  sp, sp, #16",
    "    sub  sp, sp, #288",
    "    stp  x0,  x1,  [sp, #0x00]",
    "    stp  x2,  x3,  [sp, #0x10]",
    "    stp  x4,  x5,  [sp, #0x20]",
    "    stp  x6,  x7,  [sp, #0x30]",
    "    stp  x8,  x9,  [sp, #0x40]",
    "    stp  x10, x11, [sp, #0x50]",
    "    stp  x12, x13, [sp, #0x60]",
    "    stp  x14, x15, [sp, #0x70]",
    "    stp  x16, x17, [sp, #0x80]",
    "    stp  x18, x29, [sp, #0x90]",
    "    str  x30,      [sp, #0xa0]",
    "    mrs  x9,  elr_el1",
    "    mrs  x10, spsr_el1",
    "    stp  x9,  x10, [sp, #0xb0]",
    "    mrs  x9,  sp_el0",
    "    str  x9,       [sp, #0xc0]",
    "    stp  x19, x20, [sp, #0xd0]",
    "    stp  x21, x22, [sp, #0xe0]",
    "    stp  x23, x24, [sp, #0xf0]",
    "    stp  x25, x26, [sp, #0x100]",
    "    stp  x27, x28, [sp, #0x110]",
    // Per-CPU SVC-frame base: store SP into THIS CPU's per-CPU area
    // (TPIDR_EL1 + 24), not a shared global — two CPUs in `svc` at once
    // must not clobber each other's frame pointer (SP_EL0 poison on the
    // wrong-frame restore). Slot @24: cpu_id@0, preempt_next@8, cur@16.
    "    mrs  x9, tpidr_el1",
    "    mov  x10, sp",
    "    str  x10, [x9, #24]",
    "    mov  x0, sp",
    "    bl   oxide_arm_software_step_handler",
    "    str  x0,       [sp, #0xc8]",
    "oxide_lower_sync_restore:",
    // F51: arm SS bits if Task.singlestep is set. Hook ORs (1<<21)
    // into the saved SPSR slot at [sp+0xb8] and writes MDSCR_EL1.SS.
    // Hook clobbers x0..x15; the post-hook restores reload
    // everything we care about from the frame.
    "    mov  x0, sp",
    "    bl   oxide_arm_arm_singlestep",
    // Restore everything; load x0 LAST from the retval slot so we
    // override the user's saved x0 with the dispatcher's u64 retval
    // (SVC) or the original user x0 (software-step, no-op).
    "    ldp  x9,  x10, [sp, #0xb0]",
    "    msr  elr_el1,  x9",
    "    msr  spsr_el1, x10",
    "    ldr  x9,       [sp, #0xc0]",
    "    msr  sp_el0,   x9",
    "    ldr  x30,      [sp, #0xa0]",
    "    ldp  x18, x29, [sp, #0x90]",
    "    ldp  x16, x17, [sp, #0x80]",
    "    ldp  x14, x15, [sp, #0x70]",
    "    ldp  x12, x13, [sp, #0x60]",
    "    ldp  x10, x11, [sp, #0x50]",
    "    ldp  x8,  x9,  [sp, #0x40]",
    "    ldp  x6,  x7,  [sp, #0x30]",
    "    ldp  x4,  x5,  [sp, #0x20]",
    "    ldp  x2,  x3,  [sp, #0x10]",
    "    ldp  x0,  x1,  [sp, #0x00]",
    // Restore callee-saved x19..x28 from the SVC frame.
    "    ldp  x19, x20, [sp, #0xd0]",
    "    ldp  x21, x22, [sp, #0xe0]",
    "    ldp  x23, x24, [sp, #0xf0]",
    "    ldp  x25, x26, [sp, #0x100]",
    "    ldp  x27, x28, [sp, #0x110]",
    "    ldr  x0,       [sp, #0xc8]",
    "    add  sp, sp, #288",
    "    eret",
    // -------- EL0 undefined-instruction (EC=0) save block ----------
    // Reached only via the b.eq above (after the restore's eret, so no
    // fall-through). Frame format is byte-identical to the SVC/softstep
    // 288 B frame so SvcFrame accessors + deliver_arm work on it. The
    // hook builds a catchable SIGILL handler frame (or terminates) and
    // returns the value seeded into user x0 via the retval slot.
    "oxide_undef_save_block:",
    "    ldr  x9, [sp]",             // pop 16-B preamble, restore user x9
    "    add  sp, sp, #16",
    "    sub  sp, sp, #288",
    "    stp  x0,  x1,  [sp, #0x00]",
    "    stp  x2,  x3,  [sp, #0x10]",
    "    stp  x4,  x5,  [sp, #0x20]",
    "    stp  x6,  x7,  [sp, #0x30]",
    "    stp  x8,  x9,  [sp, #0x40]",
    "    stp  x10, x11, [sp, #0x50]",
    "    stp  x12, x13, [sp, #0x60]",
    "    stp  x14, x15, [sp, #0x70]",
    "    stp  x16, x17, [sp, #0x80]",
    "    stp  x18, x29, [sp, #0x90]",
    "    str  x30,      [sp, #0xa0]",
    "    mrs  x9,  elr_el1",
    "    mrs  x10, spsr_el1",
    "    stp  x9,  x10, [sp, #0xb0]",
    "    mrs  x9,  sp_el0",
    "    str  x9,       [sp, #0xc0]",
    "    stp  x19, x20, [sp, #0xd0]",
    "    stp  x21, x22, [sp, #0xe0]",
    "    stp  x23, x24, [sp, #0xf0]",
    "    stp  x25, x26, [sp, #0x100]",
    "    stp  x27, x28, [sp, #0x110]",
    // Per-CPU SVC-frame base: store SP into THIS CPU's per-CPU area
    // (TPIDR_EL1 + 24), not a shared global — two CPUs in `svc` at once
    // must not clobber each other's frame pointer (SP_EL0 poison on the
    // wrong-frame restore). Slot @24: cpu_id@0, preempt_next@8, cur@16.
    "    mrs  x9, tpidr_el1",
    "    mov  x10, sp",
    "    str  x10, [x9, #24]",
    "    mov  x0, sp",
    "    bl   oxide_arm_undef_handler",
    "    str  x0,       [sp, #0xc8]",
    "    b    oxide_lower_sync_restore",
    "oxide_sysreg_save_block:",
    "    ldr  x9, [sp]",
    "    add  sp, sp, #16",
    "    sub  sp, sp, #288",
    "    stp  x0,  x1,  [sp, #0x00]",
    "    stp  x2,  x3,  [sp, #0x10]",
    "    stp  x4,  x5,  [sp, #0x20]",
    "    stp  x6,  x7,  [sp, #0x30]",
    "    stp  x8,  x9,  [sp, #0x40]",
    "    stp  x10, x11, [sp, #0x50]",
    "    stp  x12, x13, [sp, #0x60]",
    "    stp  x14, x15, [sp, #0x70]",
    "    stp  x16, x17, [sp, #0x80]",
    "    stp  x18, x29, [sp, #0x90]",
    "    str  x30,      [sp, #0xa0]",
    "    mrs  x9,  elr_el1",
    "    mrs  x10, spsr_el1",
    "    stp  x9,  x10, [sp, #0xb0]",
    "    mrs  x9,  sp_el0",
    "    str  x9,       [sp, #0xc0]",
    "    stp  x19, x20, [sp, #0xd0]",
    "    stp  x21, x22, [sp, #0xe0]",
    "    stp  x23, x24, [sp, #0xf0]",
    "    stp  x25, x26, [sp, #0x100]",
    "    stp  x27, x28, [sp, #0x110]",
    "    mrs  x9, tpidr_el1",
    "    mov  x10, sp",
    "    str  x10, [x9, #24]",
    "    mov  x0, sp",
    "    mrs  x1, esr_el1",
    "    bl   oxide_arm_sysreg_trap_handler",
    "    str  x0,       [sp, #0xc8]",
    "    b    oxide_lower_sync_restore",
    ".size oxide_lower_el_sync_handler, . - oxide_lower_el_sync_handler",

    // IRQ entry per `22§5` + `14§R07`. Frame = 288 B: x0..x18,
    // x29/x30, ELR_EL1, SPSR_EL1, SP_EL0, and x19..x28. The complete
    // interrupted register set is owned by this exception frame.
    // The ELR/SPSR pair was missing pre-R07; an
    // `eret` after a context switch would have eret'd into whatever
    // ELR/SPSR currently held — wrong as soon as the dispatcher
    // swapped tasks. They sit at [sp+0xb0..0xc0] now.
    //
    // After the dispatcher returns, the asm hands the saved SPSR_EL1 to
    // `oxide_irq_resched_on_exit`, which calls the one `schedule()` iff
    // returning to EL0 with a pending resched (VOLUNTARY preempt). The
    // switch itself happens inside `schedule()`; on a fresh task the
    // saved `Context.lr` is `oxide_finish_switch_tramp` (pays the
    // `finish_task_switch` handoff) which then reaches this epilogue.
    ".balign 4",
    ".globl oxide_irq_vector_handler",
    ".type  oxide_irq_vector_handler, %function",
    "oxide_irq_vector_handler:",
    "    sub  sp, sp, #288",
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
    "    mrs  x9,  sp_el0",
    "    str  x9,       [sp, #192]",
    "    stp  x19, x20, [sp, #0xd0]",
    "    stp  x21, x22, [sp, #0xe0]",
    "    stp  x23, x24, [sp, #0xf0]",
    "    stp  x25, x26, [sp, #0x100]",
    "    stp  x27, x28, [sp, #0x110]",
    // ---- IRQ-stack switch-in (F699 per-CPU dedicated stack) ----------
    // Frame fully saved on the interrupted SP (task kstack for an EL1 IRQ;
    // SP_EL1 for an EL0 IRQ) — x0..x28,x30 are in the frame ⇒ free scratch.
    // x19 carries the interrupted frame base across the bl (dispatch is
    // extern-C ⇒ AAPCS64-preserves x19..x28); its saved value at [sp,#0xd0]
    // is restored by oxide_irq_resume_user. Run ONLY the dispatcher (incl.
    // do_softirq's deep block/ext4/net/fb re-entry) on the fresh guard-paged
    // 16 KiB IRQ stack so that tree can't overflow the interrupted task
    // kstack (the x27=0 data-abort). The FRAME stays on the task kstack, so
    // schedule() on EL0-return records the task SP in Context.sp — never the
    // shared IRQ stack. STATELESS nesting guard: if the interrupted SP is
    // already inside this CPU's IRQ stack (nested IRQ in the do_softirq
    // sti-window), keep SP — resetting to top clobbers the outer frame.
    // 16384 == sched::kstack::KSTACK_BYTES (reverse-asserted there).
    "    mov  x19, sp",                    // carry interrupted frame base
    "    mrs  x9,  tpidr_el1",
    "    ldr  x10, [x9, #32]",             // this CPU's IRQ-stack top (0 = unarmed)
    "    cbz  x10, .Lirq_dispatch_sp",     // unarmed (early boot, IRQs masked) → no switch
    "    sub  x11, x10, #16384",           // IRQ-stack low bound
    "    cmp  x19, x11",
    "    b.lo .Lirq_switch_sp",            // sp below range → outermost → switch
    "    cmp  x19, x10",
    "    b.hs .Lirq_switch_sp",            // sp at/above top → outermost → switch
    "    b    .Lirq_dispatch_sp",          // sp in [top-16K, top) → nested → keep SP
    ".Lirq_switch_sp:",
    "    mov  sp, x10",                    // outermost: run dispatch on IRQ-stack top
    ".Lirq_dispatch_sp:",
    "    bl   oxide_arm_irq_dispatch",
    "    mov  sp, x19",                    // restore interrupted frame base (no-op if nested/unarmed)
    // -- resched-on-exit (`14§R07` / smp-arch.md Phase A). One engine:
    //    pass the interrupted SPSR_EL1 (saved at [sp+184]) to the Rust slow
    //    path, which calls the single `schedule()` iff returning to EL0 with
    //    a pending resched. No IRQ-tail staging / second switch engine.
    "    ldr  x0,  [sp, #184]",             // saved SPSR_EL1
    "    bl   oxide_irq_resched_on_exit",
    "    b    oxide_irq_resume_user",
    ".size oxide_irq_vector_handler, . - oxide_irq_vector_handler",

    // Shared IRQ epilogue. Address parked as `Context.lr` on every
    // task that may be entered via the IRQ tail (per
    // `Context::new_kernel_with_irq_frame`).
    ".balign 4",
    ".globl oxide_irq_resume_user",
    ".type  oxide_irq_resume_user, %function",
    "oxide_irq_resume_user:",
    "    ldr  x9,       [sp, #192]",
    "    msr  sp_el0,   x9",
    "    ldp  x9,  x10, [sp, #176]",
    "    msr  elr_el1,  x9",
    "    msr  spsr_el1, x10",
    "    ldp  x19, x20, [sp, #0xd0]",
    "    ldp  x21, x22, [sp, #0xe0]",
    "    ldp  x23, x24, [sp, #0xf0]",
    "    ldp  x25, x26, [sp, #0x100]",
    "    ldp  x27, x28, [sp, #0x110]",
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
    "    add  sp, sp, #288",
    "    eret",
    ".size oxide_irq_resume_user, . - oxide_irq_resume_user",
);
