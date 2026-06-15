// Stack-protector support (docs/59§6 G2/G3). The compiler's
// -fstack-protector prologue stores `__stack_chk_guard` as a canary and
// the epilogue calls `__stack_chk_fail` on mismatch. The guard is a
// writable global: __libc_start_main reseeds it from auxv AT_RANDOM
// before main (G3). Low byte forced to 0 so a string overflow that
// writes up to the canary is trapped by the NUL.
#[cfg(feature = "freestanding")]
use core::cell::UnsafeCell;

#[cfg(feature = "freestanding")]
#[repr(transparent)]
struct Guard(UnsafeCell<usize>);
// SAFETY: written once at startup (single thread, before main) and read
// by compiler-emitted prologues thereafter; no concurrent mutation.
#[cfg(feature = "freestanding")]
unsafe impl Sync for Guard {}

// # C: uintptr_t __stack_chk_guard — the canary value (writable global).
#[cfg(feature = "freestanding")]
#[no_mangle]
static __stack_chk_guard: Guard = Guard(UnsafeCell::new(0xff0a_0000_0000_0000));

// Reseed the canary from auxv AT_RANDOM (called by __libc_start_main).
#[cfg(feature = "freestanding")]
pub(crate) unsafe fn reseed_from_auxv(envp: *const usize) {
    // SAFETY: envp is the kernel-provided env+auxv block; find_auxval
    // walks it within bounds to the AT_NULL terminator.
    let found = unsafe { crate::start::auxv::find_auxval(envp, crate::start::auxv::AT_RANDOM) };
    if let Some(addr) = found {
        // SAFETY: AT_RANDOM points at 16 kernel-provided random bytes;
        // reading one usize from it is in-bounds. The guard is written
        // once here before any thread or signal handler can race it.
        unsafe {
            let rnd = (addr as *const usize).read_unaligned();
            __stack_chk_guard.0.get().write(rnd & !0xff);
        }
    }
}

// # C: _Noreturn void __stack_chk_fail(void)
#[cfg(feature = "freestanding")]
#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    crate::stdlib::exit::exit_group(127)
}
