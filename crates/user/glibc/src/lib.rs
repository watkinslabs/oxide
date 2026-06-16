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
// c_variadic (printf family, stdio G6) is only exercised in the
// freestanding build; declaring it only there keeps the workspace rlib
// build free of the unused-feature warning.
#![cfg_attr(feature = "freestanding", feature(c_variadic))]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]
// A C library exposes its surface via #[no_mangle] exports, not internal
// callers; crate-internal helpers are legitimately unused in builds that
// gate out their freestanding callers. dead_code is noise here.
#![allow(dead_code)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;
// The workspace nss crate (file-format parsers); aliased because glibc has its
// own `mod nss` (the C-ABI surface) which would otherwise shadow it.
extern crate nss as libnss;
// The workspace crypt crate (sha256crypt/sha512crypt); aliased because glibc
// has its own `mod crypt` (the C-ABI surface).
extern crate crypt as libcrypt;

// Internal, no C ABI: errno TLS slot, raw syscall wrappers, sym-version
// macro, lock primitive (docs/59§3). `symver!` is #[macro_export].
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
pub mod sysinfo; //  G8 (<sys/sysinfo.h>,<unistd.h> sysconf/uname/getauxval)
pub mod search; //  G8 (<search.h>)
pub mod signal; //  G9
pub mod time; //  G10
pub mod pthread; //  G11
pub mod dlfcn; //  G12 (binds crates/user/ldso)
pub mod net; //  G13
pub mod rpc; //  Sun RPC (§9.1)
pub mod nss; //  G14 (dispatches crates/user/nss)
pub mod math; //  G15
pub mod fenv; //  G15 (<fenv.h> FP environment)
pub mod locale; //  G16
pub mod crypt; //  G17
pub mod rt; //  G17
pub mod termios; //  G17
pub mod setjmp; //  G17
pub mod ucontext; //  G17 (<ucontext.h> getcontext/setcontext/makecontext/swapcontext)
pub mod start; //  G2 csu / __libc_start_main
pub mod regex; //  G7+ (<regex.h> ERE engine)
pub mod misc; //  G8 (<syslog.h>,<err.h>,<error.h>)
pub mod obstack; //  <obstack.h> GNU memory pools
pub mod aio; //  G17 (<aio.h> POSIX async I/O over a pthread worker pool)

// Freestanding final-artifact requirements (cdylib/staticlib). Active
// only under `--features freestanding` (set by `xtask glibc`). In the
// workspace rlib + hosted/test builds the #[no_mangle] C exports stay
// off so they don't clash with the host libc the test binary links.
// The Rust #[global_allocator] for the shipped libc lives in
// malloc::api (G5), routing through the real heap.
#[cfg(feature = "freestanding")]
mod freestanding {
    // # C: void abort path for libc panics in the shipped artifact.
    #[panic_handler]
    fn panic(_info: &core::panic::PanicInfo) -> ! {
        // SAFETY: SYS_exit_group with status 127; no memory touched, no
        // return, terminating the process is the only sound libc-panic action.
        unsafe { crate::arch::syscall::sys1(crate::internal::nr::EXIT_GROUP, 127) };
        // SAFETY: exit_group(127) never returns; the kernel has destroyed
        // the process so this point is provably unreachable.
        unsafe { core::hint::unreachable_unchecked() }
    }
}
