// x86_64 Linux module retpoline thunk compatibility symbols.
//
// These are architecture-owned because Linux-built x86 modules can carry
// compiler-emitted calls to external retpoline/return thunk symbols.

#![cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]

core::arch::global_asm!(
    ".section .text",
    ".globl __x86_return_thunk",
    ".type  __x86_return_thunk, @function",
    "__x86_return_thunk:",
    "    ret",
    ".size __x86_return_thunk, . - __x86_return_thunk",

    ".globl __x86_indirect_thunk_rax",
    ".type  __x86_indirect_thunk_rax, @function",
    "__x86_indirect_thunk_rax:",
    "    jmp rax",
    ".size __x86_indirect_thunk_rax, . - __x86_indirect_thunk_rax",

    ".globl __x86_indirect_thunk_rbx",
    ".type  __x86_indirect_thunk_rbx, @function",
    "__x86_indirect_thunk_rbx:",
    "    jmp rbx",
    ".size __x86_indirect_thunk_rbx, . - __x86_indirect_thunk_rbx",

    ".globl __x86_indirect_thunk_rcx",
    ".type  __x86_indirect_thunk_rcx, @function",
    "__x86_indirect_thunk_rcx:",
    "    jmp rcx",
    ".size __x86_indirect_thunk_rcx, . - __x86_indirect_thunk_rcx",

    ".globl __x86_indirect_thunk_rdx",
    ".type  __x86_indirect_thunk_rdx, @function",
    "__x86_indirect_thunk_rdx:",
    "    jmp rdx",
    ".size __x86_indirect_thunk_rdx, . - __x86_indirect_thunk_rdx",

    ".globl __x86_indirect_thunk_r8",
    ".type  __x86_indirect_thunk_r8, @function",
    "__x86_indirect_thunk_r8:",
    "    jmp r8",
    ".size __x86_indirect_thunk_r8, . - __x86_indirect_thunk_r8",

    ".globl __x86_indirect_thunk_r10",
    ".type  __x86_indirect_thunk_r10, @function",
    "__x86_indirect_thunk_r10:",
    "    jmp r10",
    ".size __x86_indirect_thunk_r10, . - __x86_indirect_thunk_r10",

    ".globl __x86_indirect_thunk_r12",
    ".type  __x86_indirect_thunk_r12, @function",
    "__x86_indirect_thunk_r12:",
    "    jmp r12",
    ".size __x86_indirect_thunk_r12, . - __x86_indirect_thunk_r12",

    ".globl __x86_indirect_thunk_r14",
    ".type  __x86_indirect_thunk_r14, @function",
    "__x86_indirect_thunk_r14:",
    "    jmp r14",
    ".size __x86_indirect_thunk_r14, . - __x86_indirect_thunk_r14",
);

unsafe extern "C" {
    pub fn __x86_return_thunk();
    pub fn __x86_indirect_thunk_rax();
    pub fn __x86_indirect_thunk_rbx();
    pub fn __x86_indirect_thunk_rcx();
    pub fn __x86_indirect_thunk_rdx();
    pub fn __x86_indirect_thunk_r8();
    pub fn __x86_indirect_thunk_r10();
    pub fn __x86_indirect_thunk_r12();
    pub fn __x86_indirect_thunk_r14();
}
