// __libc_start_main — glibc's C runtime entry (docs/59§6 G2). Called by
// _start with the app's `main` + the initial argc/argv. Computes envp,
// runs main, and exits with its return code. The full version (init/
// preinit arrays, __environ, atexit/fini, TLS, auxv parse) fills in at
// G2+/G7/G11; G2 ships the static single-thread path.

// envp = argv + argc + 1 (skip the args and their NULL terminator).
// Pure pointer arithmetic — testable without a real stack.
#[inline]
pub(crate) unsafe fn envp_of(argv: *mut *mut u8, argc: i32) -> *mut *mut u8 {
    // SAFETY: argv points at argc pointers followed by a NULL then envp,
    // per the SysV initial process stack; offset stays inside that block.
    unsafe { argv.add(argc as usize + 1) }
}

#[cfg(feature = "freestanding")]
type MainFn = extern "C" fn(i32, *mut *mut u8, *mut *mut u8) -> i32;

// # C: int __libc_start_main(main, argc, argv, init, fini, rtld_fini, stack_end)
#[cfg(feature = "freestanding")]
#[no_mangle]
pub unsafe extern "C" fn __libc_start_main(
    main: MainFn,
    argc: i32,
    argv: *mut *mut u8,
    _init: usize,
    _fini: usize,
    _rtld_fini: usize,
    _stack_end: *mut u8,
) -> i32 {
    // SAFETY: argv/argc come from the kernel-provided initial stack, so
    // envp_of's offset stays within the auxv block laid out below argv.
    let envp = unsafe { envp_of(argv, argc) };
    // Seed the stack-protector canary from auxv AT_RANDOM before any
    // -fstack-protector frame runs (G3).
    // SAFETY: envp points at the kernel-provided env+auxv block, the
    // contract reseed_from_auxv requires.
    unsafe { crate::start::stack_guard::reseed_from_auxv(envp as *const usize) };
    // G2+: store __environ, run __libc_csu_init / preinit+init arrays here.
    let code = main(argc, argv, envp);
    crate::stdlib::exit::exit(code) // diverges; coerces to i32
}

#[cfg(test)]
mod tests {
    use super::envp_of;
    #[test]
    fn envp_skips_args_and_null() {
        // [a0, a1, NULL, e0, ...]  argc=2 → envp at index 3
        let mut slots: [*mut u8; 5] = [1 as _, 2 as _, core::ptr::null_mut(), 9 as _, core::ptr::null_mut()];
        let argv = slots.as_mut_ptr();
        // SAFETY: argv is a live 5-elem array; index 3 (argc=2 +1) is in bounds.
        let envp = unsafe { envp_of(argv, 2) };
        // SAFETY: argv is a live 5-elem array; index 3 is in bounds.
        assert_eq!(unsafe { envp.offset_from(argv) }, 3);
        // SAFETY: index 3 of the live 5-elem array holds env slot 0 (9).
        assert_eq!(unsafe { *envp } as usize, 9);
    }
}
