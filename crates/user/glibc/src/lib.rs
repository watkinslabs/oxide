// oxide-libc — our glibc-ABI C standard library, written in Rust.
// Spec: docs/59. Emits libc.so.6 + ld-linux-* (rtld in crates/user/ldso).
//
// Layout mirrors glibc dirs (docs/59§3): one public C function (or a
// tight group) per file. C-ABI surface = `#[no_mangle] pub extern "C"`
// symbols, version-tagged via glibc.ld.version at link (docs/59§2 R02).
//
// This crate builds two ways:
//   - rlib (default): joins the workspace + hosted oracle tests.
//   - cdylib/staticlib (feature `freestanding`, via `xtask glibc`):
//     the shipped libc, no_std final artifact.
#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;

// Internal, no C ABI: errno TLS slot, raw syscall wrappers, sym-version
// macro, lock primitive (docs/59§3).
#[macro_use]
pub mod internal;

// Per-arch: syscall asm, _start, TLS setup, IFUNC variants, setjmp/clone
// asm (docs/59§3 sysdeps).
pub mod arch;

// C-library areas (docs/59§3). Empty until their G-sub-phase (docs/59§6);
// declared now so the tree + module paths are stable.
pub mod ctype; //  G4
pub mod string; //  G4
pub mod malloc; //  G5
pub mod stdio; //  G6
pub mod stdlib; //  G7
pub mod posix; //  G8
pub mod signal; //  G9
pub mod time; //  G10
pub mod pthread; //  G11
pub mod dlfcn; //  G12 (binds crates/user/ldso)
pub mod net; //  G13
pub mod nss; //  G14 (dispatches crates/user/nss)
pub mod math; //  G15
pub mod locale; //  G16
pub mod crypt; //  G17
pub mod rt; //  G17
pub mod termios; //  G17
pub mod setjmp; //  G17
pub mod start; //  G2 csu / __libc_start_main

// Freestanding final-artifact requirements (cdylib/staticlib). Inert in
// rlib + hosted/test builds.
#[cfg(all(not(test), not(feature = "hosted")))]
mod freestanding {
    // # C: void abort path for libc panics in the shipped artifact.
    #[panic_handler]
    fn panic(_info: &core::panic::PanicInfo) -> ! {
        // SAFETY: SYS_exit_group with status 127; no memory touched, no
        // return, terminating the process is the only sound libc-panic action.
        unsafe { crate::arch::syscall::sys1(crate::internal::nr::EXIT_GROUP, 127) };
        loop {}
    }
}
