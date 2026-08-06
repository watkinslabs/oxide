// CPU-exception fault handler per `22§4`.
//
// Replaces the silent `cli; hlt; jmp 1b` default with per-vector stubs
// that capture the vector number, normalize the optional CPU-pushed
// error code, and tail into a Rust printer that emits a one-line
// fault summary via `klog::write_raw`. Then halts.
//
// Stack layout at `oxide_fault_common` entry (after stub pushes):
//   [rsp + 0x00]  vector       (stub-pushed)
//   [rsp + 0x08]  error_code   (CPU-pushed for vec 8/10..14/17/21,
//                               otherwise stub-pushed 0)
//   [rsp + 0x10]  RIP          (CPU-pushed)
//   [rsp + 0x18]  CS           (CPU-pushed)
//   [rsp + 0x20]  RFLAGS       (CPU-pushed)
//   [rsp + 0x28]  RSP          (CPU-pushed)
//   [rsp + 0x30]  SS           (CPU-pushed)
//
// CR2 holds the page-fault linear address for vector 14.

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text",

    // ----- per-vector stubs --------------------------------------------------
    // Macros: with-err vs no-err. Vectors 8/10/11/12/13/14/17/21 push an
    // error code; others don't. We always synthesize a slot so the common
    // path sees a uniform layout.
    ".macro VECNE vec",         // no error code on stack
    "    push 0",
    "    push \\vec",
    "    jmp oxide_fault_common",
    ".endm",
    ".macro VECE  vec",         // error code already on stack
    "    push \\vec",
    "    jmp oxide_fault_common",
    ".endm",
    // Paranoid flavours, for the four IST-routed vectors (`install_ist_gates`:
    // #DB=1, NMI=2, #DF=8, #MC=18). Those can arrive with CPL already 0 and GS
    // still holding the USER base — the window between an exit path's `swapgs`
    // and its `sysretq`/`iretq` — so the saved-CS test the other 29 vectors use
    // gives the wrong answer for them.
    ".macro VECNEP vec",        // no error code on stack, paranoid
    "    push 0",
    "    push \\vec",
    "    jmp oxide_fault_paranoid",
    ".endm",
    ".macro VECEP  vec",        // error code already on stack, paranoid
    "    push \\vec",
    "    jmp oxide_fault_paranoid",
    ".endm",

    ".globl oxide_vec_0", "oxide_vec_0:",  "VECNE 0",
    ".globl oxide_vec_1", "oxide_vec_1:",  "VECNEP 1",
    ".globl oxide_vec_2", "oxide_vec_2:",  "VECNEP 2",
    ".globl oxide_vec_3", "oxide_vec_3:",  "VECNE 3",
    ".globl oxide_vec_4", "oxide_vec_4:",  "VECNE 4",
    ".globl oxide_vec_5", "oxide_vec_5:",  "VECNE 5",
    ".globl oxide_vec_6", "oxide_vec_6:",  "VECNE 6",
    ".globl oxide_vec_7", "oxide_vec_7:",  "VECNE 7",
    ".globl oxide_vec_8", "oxide_vec_8:",  "VECEP  8",
    ".globl oxide_vec_9", "oxide_vec_9:",  "VECNE 9",
    ".globl oxide_vec_10","oxide_vec_10:", "VECE  10",
    ".globl oxide_vec_11","oxide_vec_11:", "VECE  11",
    ".globl oxide_vec_12","oxide_vec_12:", "VECE  12",
    ".globl oxide_vec_13","oxide_vec_13:", "VECE  13",
    ".globl oxide_vec_14","oxide_vec_14:", "VECE  14",
    ".globl oxide_vec_15","oxide_vec_15:", "VECNE 15",
    ".globl oxide_vec_16","oxide_vec_16:", "VECNE 16",
    ".globl oxide_vec_17","oxide_vec_17:", "VECE  17",
    ".globl oxide_vec_18","oxide_vec_18:", "VECNEP 18",
    ".globl oxide_vec_19","oxide_vec_19:", "VECNE 19",
    ".globl oxide_vec_20","oxide_vec_20:", "VECNE 20",
    ".globl oxide_vec_21","oxide_vec_21:", "VECE  21",
    ".globl oxide_vec_22","oxide_vec_22:", "VECNE 22",
    ".globl oxide_vec_23","oxide_vec_23:", "VECNE 23",
    ".globl oxide_vec_24","oxide_vec_24:", "VECNE 24",
    ".globl oxide_vec_25","oxide_vec_25:", "VECNE 25",
    ".globl oxide_vec_26","oxide_vec_26:", "VECNE 26",
    ".globl oxide_vec_27","oxide_vec_27:", "VECNE 27",
    ".globl oxide_vec_28","oxide_vec_28:", "VECNE 28",
    ".globl oxide_vec_29","oxide_vec_29:", "VECNE 29",
    ".globl oxide_vec_30","oxide_vec_30:", "VECNE 30",
    ".globl oxide_vec_31","oxide_vec_31:", "VECNE 31",
    // Pooled stub for vectors >= 32 (no CPU error code).
    ".globl oxide_vec_default", "oxide_vec_default:", "VECNE 0xff",

    // ----- common path -------------------------------------------------------
    // Frame layout at stub-tail entry:
    //   [vec][err][rip][cs][rflags][rsp][ss]  = 7 × 8 = 56 bytes
    // CPU pushed 5 (no-err) or 6 (with-err) words; stub pushed 2 or 1.
    //
    // We save *all* caller-saved GPRs before calling the Rust
    // dispatcher so that on a recoverable fault (handler returns
    // true) the retry executes with the original register state
    // intact. SysV preserves rbx/rbp/r12-r15 across the call, but
    // rax/rcx/rdx/rsi/rdi/r8-r11 must be saved by us. Without this,
    // a #PF at e.g. `mov %rax, [%rsi+disp]` would retry with a
    // clobbered `%rsi` and re-fault at a garbage address.
    //
    // B45: capture callee-saved (rbx/rbp/r12-r15) in addition to
    // caller-saved so the #GP diagnostic can name the bad register.
    // The 15 GPR pushes sit directly below the stub's (vec, err) pair
    // and the CPU's IRETQ image, so rsp after them IS a `PtRegs`
    // (`pt_regs.rs`, offsets 0x00 r15 … 0xa8 ss, size 0xb0):
    //   [rsp+0x00]  r15   [rsp+0x30]  r11   [rsp+0x60]  rdx
    //   [rsp+0x08]  r14   [rsp+0x38]  r10   [rsp+0x68]  rcx
    //   [rsp+0x10]  r13   [rsp+0x40]  r9    [rsp+0x70]  rax
    //   [rsp+0x18]  r12   [rsp+0x48]  r8    [rsp+0x78]  vector
    //   [rsp+0x20]  rbp   [rsp+0x50]  rdi   [rsp+0x80]  error
    //   [rsp+0x28]  rbx   [rsp+0x58]  rsi   [rsp+0x88..0xa8] iretq image
    // Rust dispatcher gets rdi = *mut PtRegs.
    //
    // SysV stack alignment: the CPU 16-aligns RSP before pushing the
    // 5-quadword IRETQ image (Intel SDM Vol. 3 §6.14.2), so RSP ≡ 8
    // (mod 16) once the stub's (vec, err) pair makes the tag+image an
    // odd 7 quadwords — the SAME state `oxide_irq_common` reasons from.
    // 15 pushes (0x78) then leave RSP ≡ 0 (mod 16), which is exactly
    // what SysV wants AT a `call`. The prior `sub rsp, 8` "align" pad
    // made it ≡ 8 and left the callee entered at rsp ≡ 0 (mod 16),
    // i.e. misaligned; it is gone.
    //
    // GS handling. Both entries leave `ebx` = "this entry ran a swapgs", and
    // `oxide_fault_body`'s tail undoes exactly that — Linux's paranoid-exit
    // shape, kept for the regular path too so entry and exit can never
    // disagree about a frame the handler edited. `ebx` is SysV callee-saved,
    // so it survives both Rust calls (and a `schedule()` inside them); the
    // interrupted rbx is already in the frame and is popped back below.
    ".globl oxide_fault_common",
    ".type  oxide_fault_common, @function",
    "oxide_fault_common:",
    "    cld",
    "    push rax",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    push rbx",
    "    push rbp",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    // Regular vectors: the saved CS names the interrupted ring. RPL 3 ⇒ GS
    // still holds the user base ⇒ swap the kernel per-CPU base in. RPL 0 ⇒
    // kernel base already live, because the only kernel-mode code running on
    // a user GS base is the two-instruction `swapgs`/return window, and the
    // faults reachable there are IST-routed to `oxide_fault_paranoid`.
    // The one exception the CS test still gets wrong: the returning `iretq`
    // itself faulting (#GP/#SS/#PF on a corrupt frame image) reports a kernel
    // CS while GS is the user base, so the diagnostic below runs on the wrong
    // per-CPU area. That frame is already unrecoverable; the cost is a worse
    // death, not a live wrong answer.
    "    xor  ebx, ebx",
    "    test byte ptr [rsp + 0x90], 3", // PtRegs.cs
    "    jz   oxide_fault_body",
    "    swapgs",
    "    mov  ebx, 1",
    "    jmp  oxide_fault_body",
    ".size oxide_fault_common, . - oxide_fault_common",

    // ----- paranoid path (#DB, NMI, #DF, #MC) --------------------------------
    // Same frame, different GS decision. These four are IST-routed
    // (`install_ist_gates`) precisely because they can fire anywhere,
    // including at CPL 0 with the USER GS base live. Read the live GS base
    // instead of trusting the saved CS: `CR4.FSGSBASE` is held clear
    // (`msr::CR4_FSGSBASE`), so ring 3 cannot install a base of its own and
    // every user base is a `TASK_SIZE_MAX`-bounded, bit-63-clear value, while
    // every per-CPU area is in the upper canonical half. Bit 63 set therefore
    // proves the kernel base is already live (`msr::gs_base_is_kernel`).
    ".globl oxide_fault_paranoid",
    ".type  oxide_fault_paranoid, @function",
    "oxide_fault_paranoid:",
    "    cld",
    "    push rax",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    push rbx",
    "    push rbp",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    // rdmsr clobbers eax/ecx/edx; the interrupted values are already framed.
    "    xor  ebx, ebx",
    "    mov  ecx, {msr_gs_base}",
    "    rdmsr",                         // edx:eax = IA32_GS_BASE
    "    test edx, edx",
    "    js   oxide_fault_body",         // bit 63 set ⇒ kernel base already live
    "    swapgs",
    "    mov  ebx, 1",
    ".size oxide_fault_paranoid, . - oxide_fault_paranoid",

    ".type  oxide_fault_body, @function",
    "oxide_fault_body:",
    // Linux `exc_page_fault` inherits the interrupted process IRQ state before
    // running the memory-fault handler. Enable only for #PF frames whose saved
    // RFLAGS had IF set: a fault in hard-IRQ/IRQ-off kernel context must remain
    // atomic, while user faults and uaccess faults from syscalls may sleep.
    "    cmp  qword ptr [rsp + 0x78], 14",
    "    jne  4f",
    "    test qword ptr [rsp + 0x98], 0x200",
    "    jz   4f",
    "    sti",
    "4:",
    "    mov  rdi, rsp",                 // arg 0 = *mut PtRegs (rsp IS the frame base)
    "    call oxide_fault_print_rust",   // returns bool in al
    // The common exception exit and return-to-user work require IRQs masked.
    "    cli",
    "    test al, al",
    "    jnz 2f",
    "    cli",
    "1:  hlt",
    "    jmp 1b",
    // Linux `exc_page_fault` and friends end in `irqentry_exit(regs, state)`,
    // whose `user_mode(regs)` arm runs `exit_to_user_mode_loop`. A RESOLVED
    // exception returning to CPL3 therefore delivers any signal posted while
    // the task was faulting — including the SIGTRAP the #DB user-trap hook
    // just queued — instead of holding it until the next `syscall`. The Rust
    // side is a no-op for a kernel-mode return (saved CS RPL 0), which is what
    // makes this safe on the exception-table fixup path.
    // RSP is the `PtRegs` base here and 16-aligned, as at the call above.
    "2:  mov  rdi, rsp",
    "    call oxide_irq_exit_to_user",
    // Undo whatever the entry did. `cli` first: fault handling runs with IRQs
    // on (the demand-paging path blocks on block I/O), and an IRQ taken
    // between the swapgs and the `iretq` would enter `oxide_irq_common`,
    // read a kernel CS, skip its own swapgs and dispatch on the user GS base.
    // `iretq` reloads RFLAGS from the frame, so IF comes back. No `gs:[…]`
    // access may follow.
    "    cli",
    "    test ebx, ebx",
    "    jz   3f",
    "    swapgs",
    "3:",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbp",
    "    pop rbx",
    "    pop r11",
    "    pop r10",
    "    pop r9",
    "    pop r8",
    "    pop rdi",
    "    pop rsi",
    "    pop rdx",
    "    pop rcx",
    "    pop rax",
    "    add rsp, 16",                   // drop synthetic vec + err
    "    iretq",
    ".size oxide_fault_body, . - oxide_fault_body",
    msr_gs_base = const crate::msr::IA32_GS_BASE,
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_vec_0();
    fn oxide_vec_1();
    fn oxide_vec_2();
    fn oxide_vec_3();
    fn oxide_vec_4();
    fn oxide_vec_5();
    fn oxide_vec_6();
    fn oxide_vec_7();
    fn oxide_vec_8();
    fn oxide_vec_9();
    fn oxide_vec_10();
    fn oxide_vec_11();
    fn oxide_vec_12();
    fn oxide_vec_13();
    fn oxide_vec_14();
    fn oxide_vec_15();
    fn oxide_vec_16();
    fn oxide_vec_17();
    fn oxide_vec_18();
    fn oxide_vec_19();
    fn oxide_vec_20();
    fn oxide_vec_21();
    fn oxide_vec_22();
    fn oxide_vec_23();
    fn oxide_vec_24();
    fn oxide_vec_25();
    fn oxide_vec_26();
    fn oxide_vec_27();
    fn oxide_vec_28();
    fn oxide_vec_29();
    fn oxide_vec_30();
    fn oxide_vec_31();
    fn oxide_vec_default();
}

/// Address of the per-vector stub for `vec`. Vectors >= 32 share
/// `oxide_vec_default`. On host the asm symbols are absent.
/// # C: O(1)
pub fn vector_stub_addr(vec: u8) -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let f: unsafe extern "C" fn() = match vec {
            0  => oxide_vec_0,  1  => oxide_vec_1,  2  => oxide_vec_2,  3  => oxide_vec_3,
            4  => oxide_vec_4,  5  => oxide_vec_5,  6  => oxide_vec_6,  7  => oxide_vec_7,
            8  => oxide_vec_8,  9  => oxide_vec_9,  10 => oxide_vec_10, 11 => oxide_vec_11,
            12 => oxide_vec_12, 13 => oxide_vec_13, 14 => oxide_vec_14, 15 => oxide_vec_15,
            16 => oxide_vec_16, 17 => oxide_vec_17, 18 => oxide_vec_18, 19 => oxide_vec_19,
            20 => oxide_vec_20, 21 => oxide_vec_21, 22 => oxide_vec_22, 23 => oxide_vec_23,
            24 => oxide_vec_24, 25 => oxide_vec_25, 26 => oxide_vec_26, 27 => oxide_vec_27,
            28 => oxide_vec_28, 29 => oxide_vec_29, 30 => oxide_vec_30, 31 => oxide_vec_31,
            _  => oxide_vec_default,
        };
        f as *const () as usize as u64
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    {
        let _ = vec;
        0
    }
}
