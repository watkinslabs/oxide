// setjmp x86_64 register save/restore (docs/59§6 G17d, §54). Intel syntax.
// __jmpbuf layout: [0]=rbx [8]=rbp [16]=r12 [24]=r13 [32]=r14 [40]=r15
// [48]=rsp(caller) [56]=rip(return). setjmp/_setjmp pass savemask in esi then
// tail-jump __sigsetjmp; __sigsetjmp saves regs and tail-calls __sigjmp_save
// (Rust) which returns 0. __longjmp_regs restores and jumps to the saved rip.

core::arch::global_asm!(
    ".text",
    ".globl setjmp",  ".type setjmp,@function",
    "setjmp:",
    "  xor esi, esi",            // glibc: setjmp does not save the signal mask
    "  jmp __sigsetjmp",
    ".size setjmp, .-setjmp",

    ".globl _setjmp", ".type _setjmp,@function",
    "_setjmp:",
    "  xor esi, esi",
    "  jmp __sigsetjmp",
    ".size _setjmp, .-_setjmp",

    ".globl __sigsetjmp", ".type __sigsetjmp,@function",
    "__sigsetjmp:",                // rdi = env, esi = savemask
    "  mov [rdi], rbx",
    "  mov [rdi+8], rbp",
    "  mov [rdi+16], r12",
    "  mov [rdi+24], r13",
    "  mov [rdi+32], r14",
    "  mov [rdi+40], r15",
    "  lea rax, [rsp+8]",          // caller rsp (past our return addr)
    "  mov [rdi+48], rax",
    "  mov rax, [rsp]",            // return address
    "  mov [rdi+56], rax",
    "  jmp __sigjmp_save",         // (env, savemask) → returns 0 to our caller
    ".size __sigsetjmp, .-__sigsetjmp",

    ".globl __longjmp_regs", ".type __longjmp_regs,@function",
    "__longjmp_regs:",             // rdi = env, esi = val (already normalised)
    "  mov rbx, [rdi]",
    "  mov rbp, [rdi+8]",
    "  mov r12, [rdi+16]",
    "  mov r13, [rdi+24]",
    "  mov r14, [rdi+32]",
    "  mov r15, [rdi+40]",
    "  mov rsp, [rdi+48]",
    "  mov rdx, [rdi+56]",         // saved rip
    "  mov eax, esi",              // return value
    "  jmp rdx",
    ".size __longjmp_regs, .-__longjmp_regs",
);
