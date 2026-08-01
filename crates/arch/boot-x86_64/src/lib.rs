// x86_64 bootloader handoff per docs/36 + docs/20.
//
// GRUB loads the kernel ELF directly via multiboot2: it scans the first
// 32 KiB for the header in `mb2.rs`, whose entry-address tag points at
// the 32-bit `_mb2_entry` trampoline. The trampoline builds boot page
// tables (identity + higher-half + HHDM), enters long mode, and
// tail-calls `_start` in `.text.boot` (per linker script `07§6`).
// `_start` swaps to the kernel stack and calls `_start_rust`, which
// parses the multiboot2 info struct into a `BootInfo` and tail-calls
// `kmain::kernel_main`. UART (16550A on QEMU `-serial stdio`) lives
// here so klog has a sink before any driver exists.

#![no_std]
#![cfg_attr(target_os = "oxide-kernel", no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

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

pub use boot_info_build::stub_boot_info;

#[cfg(test)]
mod tests;
