// x86_64 bootloader handoff per docs/36 + docs/20.
//
// Limine bootloader reads request markers from `.limine_reqs` (custom
// linker section) and writes responses, then jumps to the kernel
// entry. Our `_start` lives in `.text.boot` (per linker script
// 07§6), runs with paging set up by Limine to identity-map the
// kernel image at the upper-half virtual address.
//
// Phase 0 scope: get a `_start` symbol that runs cleanly in QEMU under
// Limine, sets up the kernel stack, parses Limine memmap into our
// `BootInfo`, and tail-calls `kmain::kernel_main`. UART driver
// (16550A on QEMU `-serial stdio`) lands here so klog has a sink.
//
// Real Limine integration + 16550 driver land in P0-07 follow-ups;
// this is the typed shell.

#![no_std]
#![cfg_attr(target_os = "oxide-kernel", no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod limine;
pub mod mb2;
pub mod uart;

// Per `04§4.0` (R06): every klog::* call site in this crate sits
// behind `debug-boot` — UART sink install, CPU/MMU dump, byte
// emit. Default builds emit zero log bytes; the call sites are
// absent from the binary, not "filtered at runtime".
// (Every expansion site is inside an `#[cfg(target_os = "oxide-kernel")]`
// entry fn, so the definition carries the same gate.)
#[cfg(all(target_os = "oxide-kernel", feature = "debug-boot"))]
macro_rules! debug_boot { ($($t:tt)*) => { $($t)* } }
#[cfg(all(target_os = "oxide-kernel", not(feature = "debug-boot")))]
macro_rules! debug_boot { ($($t:tt)*) => {} }

mod boot_debug;
mod boot_info_build;
mod entry;
mod requests;

pub use boot_info_build::stub_boot_info;
pub use requests::{LIMINE_EXECUTABLE_FILE, LIMINE_HHDM, LIMINE_KERNEL_FILE, LIMINE_MEMMAP, LIMINE_RSDP, LIMINE_SMP};

#[cfg(test)]
mod tests;
