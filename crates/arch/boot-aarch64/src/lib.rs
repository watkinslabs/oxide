// aarch64 bootloader handoff per docs/36 + docs/21 — Limine-free.
//
// Both live arm boot paths enter through the arm64 Image protocol
// trampoline in `selfboot.rs`:
//   - GRUB `linux` / UEFI LoadImage: MMU on, x0=EFI handle, x1=systab;
//     the EFI stub finds the DTB + ACPI RSDP in the firmware config
//     table, ExitBootServices, drops the MMU, then runs the trampoline.
//   - QEMU `-kernel` / U-Boot `booti`: MMU off, x0=DTB phys.
// The trampoline drops EL2->EL1 (if needed), builds identity + higher-
// half + HHDM page tables, enables the MMU, jumps to the kernel's
// higher-half VMA, then tail-calls the shared `_start` (which installs
// SP_EL1 and tail-calls `_start_rust`). `_start_rust` parses the DTB
// `/memory` node into a `BootInfo` memmap and tail-calls
// `kmain::kernel_main`. UART = PL011 at the QEMU `virt` machine's
// 0x09000000, reachable via the trampoline-installed HHDM device block.

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

pub mod dtb;
pub mod efi_cmdline;
pub mod pl011;
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub mod selfboot;

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
