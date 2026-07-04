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

    ".globl oxide_vec_0", "oxide_vec_0:",  "VECNE 0",
    ".globl oxide_vec_1", "oxide_vec_1:",  "VECNE 1",
    ".globl oxide_vec_2", "oxide_vec_2:",  "VECNE 2",
    ".globl oxide_vec_3", "oxide_vec_3:",  "VECNE 3",
    ".globl oxide_vec_4", "oxide_vec_4:",  "VECNE 4",
    ".globl oxide_vec_5", "oxide_vec_5:",  "VECNE 5",
    ".globl oxide_vec_6", "oxide_vec_6:",  "VECNE 6",
    ".globl oxide_vec_7", "oxide_vec_7:",  "VECNE 7",
    ".globl oxide_vec_8", "oxide_vec_8:",  "VECE  8",
    ".globl oxide_vec_9", "oxide_vec_9:",  "VECNE 9",
    ".globl oxide_vec_10","oxide_vec_10:", "VECE  10",
    ".globl oxide_vec_11","oxide_vec_11:", "VECE  11",
    ".globl oxide_vec_12","oxide_vec_12:", "VECE  12",
    ".globl oxide_vec_13","oxide_vec_13:", "VECE  13",
    ".globl oxide_vec_14","oxide_vec_14:", "VECE  14",
    ".globl oxide_vec_15","oxide_vec_15:", "VECNE 15",
    ".globl oxide_vec_16","oxide_vec_16:", "VECNE 16",
    ".globl oxide_vec_17","oxide_vec_17:", "VECE  17",
    ".globl oxide_vec_18","oxide_vec_18:", "VECNE 18",
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
    // Stack after GPR save (10 × 8 = 80 B pushed):
    // B45: capture callee-saved (rbx/rbp/r12-r15) in addition to
    // caller-saved so the #GP diagnostic can name the bad register.
    // Layout after the 15 GPR pushes (15 × 8 = 120 B = 0x78, + 0x08
    // align pad → 0x80 to the fault frame):
    //   [rsp+0x00]  (align pad)
    //   [rsp+0x08]  r15
    //   [rsp+0x10]  r14
    //   [rsp+0x18]  r13
    //   [rsp+0x20]  r12
    //   [rsp+0x28]  rbp
    //   [rsp+0x30]  rbx
    //   [rsp+0x38]  r11
    //   [rsp+0x40]  r10
    //   [rsp+0x48]  r9
    //   [rsp+0x50]  r8
    //   [rsp+0x58]  rdi
    //   [rsp+0x60]  rsi
    //   [rsp+0x68]  rdx
    //   [rsp+0x70]  rcx
    //   [rsp+0x78]  rax
    //   [rsp+0x80..]  fault frame (vec/err/rip/cs/rflags/rsp/ss)
    // Rust dispatcher gets rdi=*FaultFrame, rsi=*FaultGprs.
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
    "    sub  rsp, 8",                   // align to 16 before call
    "    lea  rdi, [rsp + 0x80]",        // arg 0 = *FaultFrame
    "    lea  rsi, [rsp + 0x08]",        // arg 1 = *FaultGprs (skip pad)
    "    call oxide_fault_print_rust",   // returns bool in al
    "    add  rsp, 8",                   // undo align
    "    test al, al",
    "    jnz 2f",
    "    cli",
    "1:  hlt",
    "    jmp 1b",
    "2:  pop r15",
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
    ".size oxide_fault_common, . - oxide_fault_common",
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
