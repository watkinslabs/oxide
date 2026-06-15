//! ldso — glibc-ABI dynamic linker / loader (docs/59§5, docs/31§5). Emits
//! `ld-linux-x86-64.so.2` / `ld-linux-aarch64.so.1`. Reuses `crate::dl`'s
//! pure reloc/parse logic; adds the freestanding mmap-based loading, the
//! self-relocation bootstrap, symbol versioning, TLS setup and program
//! handoff. Ladder: G12a self-reloc bootstrap (here), G12b dep graph +
//! mmap mapping, G12c symbol resolution, G12d versioning, G12e TLS, G12f
//! lazy PLT + init handoff, G12g dlopen family.
//!
//! G12a ships the bootstrap that must run before anything else: parse the
//! rtld's own `_DYNAMIC` array and apply its `R_*_RELATIVE` relocations
//! against its load bias, using zero external state (no allocator, no
//! libc — none is relocated yet).
#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod cache;
pub mod dynamic;
pub mod reloc;
pub mod search;

#[cfg(feature = "freestanding")]
pub mod syscall;

#[cfg(feature = "freestanding")]
mod freestanding {
    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        // The rtld has no unwinding and no libc; a panic before handoff is
        // unrecoverable — exit_group(127) like glibc's _dl_fatal_printf path.
        // SAFETY: exit_group(2) takes a scalar code and never returns; no
        // memory is dereferenced.
        unsafe { crate::syscall::exit_group(127) }
    }
}
