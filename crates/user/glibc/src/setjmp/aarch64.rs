// setjmp aarch64 register save/restore (docs/59§6 G17d, §54). GAS syntax.
// __jmpbuf layout (byte offsets): x19..x28 @0x00..0x48, x29(fp)@0x50,
// x30(lr)@0x58, sp@0x60, d8..d15 @0x68..0xA0. setjmp/_setjmp set w1=0 and
// tail-branch __sigsetjmp, which saves regs and tail-calls __sigjmp_save (Rust,
// returns 0 via the saved lr). __longjmp_regs restores and `ret`s to the
// saved lr (the sigsetjmp return point).

core::arch::global_asm!(
    ".text",
    ".globl setjmp",  ".type setjmp,%function",
    "setjmp:",
    "  mov w1, #0",                // setjmp does not save the signal mask
    "  b __sigsetjmp",
    ".size setjmp, .-setjmp",

    ".globl _setjmp", ".type _setjmp,%function",
    "_setjmp:",
    "  mov w1, #0",
    "  b __sigsetjmp",
    ".size _setjmp, .-_setjmp",

    ".globl __sigsetjmp", ".type __sigsetjmp,%function",
    "__sigsetjmp:",                // x0 = env, w1 = savemask
    "  stp x19, x20, [x0, #0]",
    "  stp x21, x22, [x0, #16]",
    "  stp x23, x24, [x0, #32]",
    "  stp x25, x26, [x0, #48]",
    "  stp x27, x28, [x0, #64]",
    "  stp x29, x30, [x0, #80]",   // fp, lr
    "  mov x2, sp",
    "  str x2, [x0, #96]",
    "  stp d8,  d9,  [x0, #104]",
    "  stp d10, d11, [x0, #120]",
    "  stp d12, d13, [x0, #136]",
    "  stp d14, d15, [x0, #152]",
    "  b __sigjmp_save",           // (env, savemask) → returns 0 to our caller
    ".size __sigsetjmp, .-__sigsetjmp",

    ".globl __longjmp_regs", ".type __longjmp_regs,%function",
    "__longjmp_regs:",             // x0 = env, w1 = val (already normalised)
    "  ldp x19, x20, [x0, #0]",
    "  ldp x21, x22, [x0, #16]",
    "  ldp x23, x24, [x0, #32]",
    "  ldp x25, x26, [x0, #48]",
    "  ldp x27, x28, [x0, #64]",
    "  ldp x29, x30, [x0, #80]",
    "  ldr x2, [x0, #96]",
    "  mov sp, x2",
    "  ldp d8,  d9,  [x0, #104]",
    "  ldp d10, d11, [x0, #120]",
    "  ldp d12, d13, [x0, #136]",
    "  ldp d14, d15, [x0, #152]",
    "  mov w0, w1",                // return value
    "  ret",                       // returns to restored x30 = setjmp ret point
    ".size __longjmp_regs, .-__longjmp_regs",
);
