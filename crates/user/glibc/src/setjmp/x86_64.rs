// setjmp x86_64 register save/restore (docs/59§6 G17d, §54). Intel syntax.
// Naked #[no_mangle] fns (not global_asm) so rustc adds setjmp/_setjmp/
// __sigsetjmp to libc.so.6's dynsym — the cdylib version script localizes any
// symbol not in rustc's export list, which raw global_asm symbols are not.
// __jmpbuf layout: [0]=rbx [8]=rbp [16]=r12 [24]=r13 [32]=r14 [40]=r15
// [48]=rsp(caller) [56]=rip(return).
use super::__jmp_buf_tag;

// setjmp/_setjmp do not save the signal mask (glibc); tail-jump __sigsetjmp.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn setjmp(_env: *mut __jmp_buf_tag) -> i32 {
    core::arch::naked_asm!("xor esi, esi", "jmp __sigsetjmp");
}
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _setjmp(_env: *mut __jmp_buf_tag) -> i32 {
    core::arch::naked_asm!("xor esi, esi", "jmp __sigsetjmp");
}

// rdi = env, esi = savemask. Save callee regs + caller rsp + return addr, then
// tail-call __sigjmp_save (Rust) which saves the mask and returns 0.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __sigsetjmp(_env: *mut __jmp_buf_tag, _savemask: i32) -> i32 {
    core::arch::naked_asm!(
        "mov [rdi], rbx",
        "mov [rdi+8], rbp",
        "mov [rdi+16], r12",
        "mov [rdi+24], r13",
        "mov [rdi+32], r14",
        "mov [rdi+40], r15",
        "lea rax, [rsp+8]",          // caller rsp (past our return addr)
        "mov [rdi+48], rax",
        "mov rax, [rsp]",            // return address
        "mov [rdi+56], rax",
        "jmp __sigjmp_save",
    );
}

// rdi = env, esi = val (already normalised). Restore + jump to saved rip.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __longjmp_regs(_env: *mut __jmp_buf_tag, _val: i32) -> ! {
    core::arch::naked_asm!(
        "mov rbx, [rdi]",
        "mov rbp, [rdi+8]",
        "mov r12, [rdi+16]",
        "mov r13, [rdi+24]",
        "mov r14, [rdi+32]",
        "mov r15, [rdi+40]",
        "mov rsp, [rdi+48]",
        "mov rdx, [rdi+56]",         // saved rip
        "mov eax, esi",              // return value
        "jmp rdx",
    );
}
