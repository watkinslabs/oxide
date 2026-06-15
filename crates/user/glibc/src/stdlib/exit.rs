// exit family (docs/59§6 G2). G2 = immediate termination. atexit /
// __cxa_atexit handler registration + stdio flush + fini-array run land
// at G7; exit() will walk those before exit_group then.

// Raw process termination. Always built (used by __libc_start_main and
// __stack_chk_fail); not a C export by itself.
#[inline]
pub fn exit_group(code: i32) -> ! {
    // SAFETY: exit_group(2) terminates every thread in the group with
    // `code` and never returns; no memory is referenced.
    unsafe { crate::arch::syscall::sys1(crate::internal::nr::EXIT_GROUP, code as usize) };
    // SAFETY: exit_group never returns; the kernel has torn down the
    // process, so control provably cannot reach this point.
    unsafe { core::hint::unreachable_unchecked() }
}

// # C: _Noreturn void exit(int)
#[cfg(feature = "freestanding")]
#[no_mangle]
pub extern "C" fn exit(code: i32) -> ! { exit_group(code) } // G7: run atexit first

// # C: _Noreturn void _exit(int) — no atexit, no flush.
#[cfg(feature = "freestanding")]
#[no_mangle]
pub extern "C" fn _exit(code: i32) -> ! { exit_group(code) }

// # C: _Noreturn void _Exit(int) — C99 alias of _exit.
#[cfg(feature = "freestanding")]
#[no_mangle]
pub extern "C" fn _Exit(code: i32) -> ! { exit_group(code) }
