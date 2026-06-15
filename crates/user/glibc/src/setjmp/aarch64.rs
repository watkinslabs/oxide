// setjmp aarch64 register save/restore (docs/59§6 G17d, §54). Naked #[no_mangle]
// fns (see x86_64.rs for why: cdylib export). __jmpbuf byte offsets: x19..x28
// @0x00..0x48, x29(fp)@0x50, x30(lr)@0x58, sp@0x60, d8..d15 @0x68..0xA0.
use super::__jmp_buf_tag;

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn setjmp(_env: *mut __jmp_buf_tag) -> i32 {
    core::arch::naked_asm!("mov w1, #0", "b __sigsetjmp");
}
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _setjmp(_env: *mut __jmp_buf_tag) -> i32 {
    core::arch::naked_asm!("mov w1, #0", "b __sigsetjmp");
}

// x0 = env, w1 = savemask. Save callee regs + sp, tail-call __sigjmp_save.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __sigsetjmp(_env: *mut __jmp_buf_tag, _savemask: i32) -> i32 {
    core::arch::naked_asm!(
        "stp x19, x20, [x0, #0]",
        "stp x21, x22, [x0, #16]",
        "stp x23, x24, [x0, #32]",
        "stp x25, x26, [x0, #48]",
        "stp x27, x28, [x0, #64]",
        "stp x29, x30, [x0, #80]",   // fp, lr
        "mov x2, sp",
        "str x2, [x0, #96]",
        "stp d8,  d9,  [x0, #104]",
        "stp d10, d11, [x0, #120]",
        "stp d12, d13, [x0, #136]",
        "stp d14, d15, [x0, #152]",
        "b __sigjmp_save",
    );
}

// x0 = env, w1 = val (already normalised). Restore + ret to saved lr.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __longjmp_regs(_env: *mut __jmp_buf_tag, _val: i32) -> ! {
    core::arch::naked_asm!(
        "ldp x19, x20, [x0, #0]",
        "ldp x21, x22, [x0, #16]",
        "ldp x23, x24, [x0, #32]",
        "ldp x25, x26, [x0, #48]",
        "ldp x27, x28, [x0, #64]",
        "ldp x29, x30, [x0, #80]",
        "ldr x2, [x0, #96]",
        "mov sp, x2",
        "ldp d8,  d9,  [x0, #104]",
        "ldp d10, d11, [x0, #120]",
        "ldp d12, d13, [x0, #136]",
        "ldp d14, d15, [x0, #152]",
        "mov w0, w1",                // return value
        "ret",
    );
}
