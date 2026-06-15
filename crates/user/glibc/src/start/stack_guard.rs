// Stack-protector support (docs/59§6 G2). The compiler's -fstack-protector
// prologue stores `__stack_chk_guard` as a canary and the epilogue calls
// `__stack_chk_fail` on mismatch. G2 ships a fixed sentinel (high byte 0
// + newline, like glibc's terminator bytes, to trap string-overflow);
// G3 reseeds it from auxv AT_RANDOM at process start.

// # C: uintptr_t __stack_chk_guard — the canary value.
#[cfg(feature = "freestanding")]
#[no_mangle]
pub static __stack_chk_guard: usize = 0xff0a_0000_0000_0000;

// # C: _Noreturn void __stack_chk_fail(void)
#[cfg(feature = "freestanding")]
#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    crate::stdlib::exit::exit_group(127)
}
