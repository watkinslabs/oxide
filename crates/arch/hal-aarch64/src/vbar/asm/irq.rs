#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".balign 4",
    ".globl oxide_irq_vector_handler",
    ".type  oxide_irq_vector_handler, %function",
    "oxide_irq_vector_handler:",
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
    "    cbz  x0, .Lspg_irq_x0",            // per-CPU area unarmed (early boot)
    "    str  x1, [x0, #48]",
    "    ldr  x1, [x0, #40]",          // this CPU's current-task kstack top
    "    cbz  x1, .Lspg_irq_x1",            // unarmed: boot/AP stack or idle task
    "    mrs  x0, spsr_el1",
    "    and  x0, x0, #0xf",          // SPSR.M[3:0]; 0 = EL0t
    "    cbz  x0, .Lspg_irq_el0",
    "    mov  x0, sp",
    "    cmp  x0, x1",                 // above the task stack's top?
    "    b.hi .Lspg_irq_irq",
    "    sub  x1, x1, #{stack_bytes}",
    "    add  x1, x1, #288",           // this frame must still fit
    "    cmp  x0, x1",
    "    b.hs .Lspg_irq_x1",               // inside the task stack: OK
    ".Lspg_irq_irq:",                      // the IRQ stack is also a valid EL1 stack
    "    mrs  x1, tpidr_el1",
    "    ldr  x1, [x1, #32]",          // irq_stack_top (0 = unarmed)
    "    cbz  x1, .Lspg_irq_bad",
    "    cmp  x0, x1",
    "    b.hi .Lspg_irq_bad",
    "    sub  x1, x1, #{stack_bytes}",
    "    add  x1, x1, #288",
    "    cmp  x0, x1",
    "    b.lo .Lspg_irq_bad",
    "    b    .Lspg_irq_x1",               // inside the IRQ stack: OK
    ".Lspg_irq_el0:",
    "    mov  sp, x1",                 // EL0 entry: SP_EL1 = kstack_top
    "    b    .Lspg_irq_x1",
    ".Lspg_irq_bad:",                      // x0 = the offending SP
    "    mrs  x1, tpidr_el1",
    "    ldr  x1, [x1, #56]",          // this CPU's overflow stack
    "    cbz  x1, .Lspg_irq_x1",           // unarmed: nothing better to do
    "    mov  sp, x1",
    "    mrs  x1, esr_el1",
    "    mrs  x2, elr_el1",
    "    mrs  x3, far_el1",
    "    mrs  x7, tpidr_el1",          // x7: bounds scratch
    "    ldr  x5, [x7, #40]",          // top
    "    sub  x4, x5, #{stack_bytes}", // lo
    "    mov  x6, #1",             // report site
    "    mov  x7, x30",            // interrupted caller's link register
    "    bl   oxide_handle_bad_stack", // never returns
    ".Lspg_irq_x1:",
    "    mrs  x0, tpidr_el1",
    "    ldr  x1, [x0, #48]",
    ".Lspg_irq_x0:",
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
    // The range bound is the same shared constant as task-stack allocation.
    "    mov  x19, sp",                    // carry interrupted frame base
    "    mrs  x9,  tpidr_el1",
    "    ldr  x10, [x9, #32]",             // this CPU's IRQ-stack top (0 = unarmed)
    "    cbz  x10, .Lirq_dispatch_sp",     // unarmed (early boot, IRQs masked) → no switch
    "    sub  x11, x10, #{stack_bytes}",    // IRQ-stack low bound
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
    // `do_softirq_own_stack` must begin with a fresh hard-IRQ stack. The
    // dispatcher above ran on that stack, so invoke the post-dispatch handoff
    // only after its frame is gone and the interrupted stack is active again.
    "    bl   oxide_arm_irq_after_dispatch",
    // -- return-to-user work loop (Linux `irqentry_exit`). The WHOLE 288 B
    //    entry frame goes to Rust as `*mut SvcFrame`: the loop needs the saved
    //    SPSR to decide user-vs-kernel return, the saved ELR for the rseq
    //    critical-section abort, and every GPR slot to build a signal frame.
    //    Passing only SPSR + &ELR (pre-B1471) is why nothing but `schedule()`
    //    could run here, and why a userspace spin loop took no signals at all.
    //    SP is the frame base again after the IRQ-stack switch-out above.
    "    mov  x0,  sp",                     // arg0 = *mut SvcFrame
    "    bl   oxide_irq_exit_to_user",
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
    stack_bytes = const hal::KERNEL_STACK_BYTES,
);

