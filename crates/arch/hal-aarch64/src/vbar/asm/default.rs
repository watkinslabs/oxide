#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
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
    // ---- entry SP guard (x86 TSS-RSP0 parity + Linux `__bad_stack`) ----
    // On an EL0 -> EL1 transition the task's kernel stack is empty BY DEFINITION,
    // so `kstack_top` is the only correct SP_EL1 — reset it rather than trust it.
    // x86 gets this for free: the ring3 -> ring0 transition reloads RSP0 from the
    // TSS, which `set_rsp0` republishes on every switch. On aarch64 SP_EL1 is a
    // live register that nothing resets, so a path that eret'd to EL0 leaving it
    // somewhere else would make the NEXT kernel entry build its frame there.
    //
    // For an EL1 -> EL1 entry the stack is legitimately in use, so SP is
    // bounds-checked instead (Linux `__bad_stack`) and a bad one is reported on a
    // per-CPU overflow stack rather than scribbling the neighbouring slot. TWO
    // ranges are valid: the current task's stack, and this CPU's hard-IRQ stack —
    // the IRQ dispatcher and its softirq drain legitimately run on the latter, so
    // checking only the task stack false-positives on every nested IRQ.
    //
    // Nothing may be pushed to get scratch registers — SP is the value in doubt.
    // x0 goes to TPIDRRO_EL0 (EL0-read-only, EL1-writable, unused by this
    // kernel), x1 to a per-CPU scratch slot; both restored before we continue.
    "    msr  tpidrro_el0, x0",
    "    mrs  x0, tpidr_el1",
    "    cbz  x0, .Lspg_dflt_x0",            // per-CPU area unarmed (early boot)
    "    str  x1, [x0, #48]",
    "    ldr  x1, [x0, #40]",          // this CPU's current-task kstack top
    "    cbz  x1, .Lspg_dflt_x1",            // unarmed: boot/AP stack or idle task
    "    mrs  x0, spsr_el1",
    "    and  x0, x0, #0xf",          // SPSR.M[3:0]; 0 = EL0t
    "    cbz  x0, .Lspg_dflt_el0",
    "    mov  x0, sp",
    "    cmp  x0, x1",                 // above the task stack's top?
    "    b.hi .Lspg_dflt_irq",
    "    sub  x1, x1, #{stack_bytes}",
    "    add  x1, x1, #288",           // this frame must still fit
    "    cmp  x0, x1",
    "    b.hs .Lspg_dflt_x1",               // inside the task stack: OK
    ".Lspg_dflt_irq:",                      // the IRQ stack is also a valid EL1 stack
    "    mrs  x1, tpidr_el1",
    "    ldr  x1, [x1, #32]",          // irq_stack_top (0 = unarmed)
    "    cbz  x1, .Lspg_dflt_bad",
    "    cmp  x0, x1",
    "    b.hi .Lspg_dflt_bad",
    "    sub  x1, x1, #{stack_bytes}",
    "    add  x1, x1, #288",
    "    cmp  x0, x1",
    "    b.lo .Lspg_dflt_bad",
    "    b    .Lspg_dflt_x1",               // inside the IRQ stack: OK
    ".Lspg_dflt_el0:",
    "    mov  sp, x1",                 // EL0 entry: SP_EL1 = kstack_top
    "    b    .Lspg_dflt_x1",
    ".Lspg_dflt_bad:",                      // x0 = the offending SP
    "    mrs  x1, tpidr_el1",
    "    ldr  x1, [x1, #56]",          // this CPU's overflow stack
    "    cbz  x1, .Lspg_dflt_x1",           // unarmed: nothing better to do
    "    mov  sp, x1",
    "    mrs  x1, esr_el1",
    "    mrs  x2, elr_el1",
    "    mrs  x3, far_el1",
    "    mrs  x7, tpidr_el1",          // x7: bounds scratch
    "    ldr  x5, [x7, #40]",          // top
    "    sub  x4, x5, #{stack_bytes}", // lo
    "    mov  x6, #0",             // report site
    "    mov  x7, x30",            // interrupted caller's link register
    "    bl   oxide_handle_bad_stack", // never returns
    ".Lspg_dflt_x1:",
    "    mrs  x0, tpidr_el1",
    "    ldr  x1, [x0, #48]",
    ".Lspg_dflt_x0:",
    "    mrs  x0, tpidrro_el0",
    // Do not leave the interrupted x0 — frequently a kernel pointer — in a
    // register userspace can read. Linux zeroes TPIDRRO_EL0 for native
    // threads in `tls_thread_switch` for the same reason.
    "    msr  tpidrro_el0, xzr",
    // ---- end entry SP guard --------------------------------------------
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
    // Linux `el0_da` restores DAIF_PROCCTX, while `el1_abort` inherits the
    // interrupted kernel state. Do the same for instruction/data aborts whose
    // saved SPSR had IRQ unmasked; every other synchronous exception remains
    // fully masked. ESR stays live in x0 and the frame owns scratch x9.
    "    lsr  x9, x0, #26",
    "    cmp  x9, #0x20",
    "    b.eq 8f",
    "    cmp  x9, #0x21",
    "    b.eq 8f",
    "    cmp  x9, #0x24",
    "    b.eq 8f",
    "    cmp  x9, #0x25",
    "    b.ne 9f",
    "8:",
    "    ldr  x9, [sp, #184]",           // saved SPSR_EL1
    "    tbnz x9, #7, 9f",               // SPSR.I set => inherit IRQ-off
    "    msr  daifclr, #2",
    "9:",
    "    bl   oxide_fault_print_rust",
    // The shared exception exit and return-to-user work require IRQs masked.
    "    msr  daifset, #2",
    "    cbz  w0, 1f",             // not handled → wfi forever
    // Linux `el0_da`/`el0_ia` end in `arm64_exit_to_user_mode(regs)`: a
    // RESOLVED exception returning to EL0 runs the same return-to-user work
    // loop an IRQ return does, so a signal posted while the task was faulting
    // is delivered now rather than at its next `svc`. The Rust side is a no-op
    // for an EL1 return (`SPSR.M != EL0t`).
    "    mov  x0,  sp",                     // arg0 = *mut SvcFrame
    "    bl   oxide_irq_exit_to_user",
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
    // Unrecoverable: park this PE for good. Quiesce the GIC CPU interface FIRST
    // (Linux `gic_cpu_if_down`: ICC_IGRPEN1_EL1 = 0), because `WFI` wake-up is
    // NOT gated by PSTATE.DAIF — per ARM ARM D1 a pending physical interrupt
    // completes WFI even while DAIF.I masks its delivery. The handler masked
    // DAIF on entry and is never going to ack the timer, so with the CPU
    // interface still enabled the periodic CNTV interrupt stays pending forever,
    // every WFI returns immediately, and `b 1b` becomes a 100%-CPU spin instead
    // of a halt — which under TCG pegs a host core for the life of the VM and
    // buried the real fault under a wedged-looking boot. With Group 1 delivery
    // off at the CPU interface nothing is signalled to the PE, so WFI genuinely
    // sleeps. `wfe` ahead of `wfi` mirrors Linux `cpu_park_loop`.
    "1:  msr  s3_0_c12_c12_7, xzr",  // ICC_IGRPEN1_EL1 = 0
    "    isb",
    "2:  wfe",
    "    wfi",
    "    b 2b",
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
    stack_bytes = const hal::KERNEL_STACK_BYTES,
);

