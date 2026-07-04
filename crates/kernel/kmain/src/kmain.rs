#![cfg(target_os = "oxide-kernel")]  // kernel-entry crate; oxide-kernel-only (wires hal/sched/tty live state)
// Kernel lib. Per-arch boot crates own _start; this lib hosts
// kernel_main. #![no_std]; oxide-kernel-only.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

// Anchor crates whose `#[no_mangle]` symbols the linker needs even
// without an explicit `use`. Per `52§8`.
#[cfg(target_os = "oxide-kernel")] extern crate fs;
#[cfg(target_os = "oxide-kernel")] extern crate arch_irq;

// Compile-time check: per-arch Context must fit in Task.arch_ctx.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
const _: () = assert!(
    core::mem::size_of::<hal_x86_64::ContextX86_64>() <= ::sched::ARCH_CTX_SIZE,
    "ContextX86_64 exceeds ::sched::ARCH_CTX_SIZE — bump the const",
);
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
const _: () = assert!(
    core::mem::size_of::<hal_aarch64::ContextAArch64>() <= ::sched::ARCH_CTX_SIZE,
    "ContextAArch64 exceeds ::sched::ARCH_CTX_SIZE — bump the const",
);

// Per-subsystem debug-trace gates per `04§3` R05 + R06.
#[macro_use]
extern crate kmacros;

// Per `04§4.0` R06: trace-only modules are cfg-gated at decl.
// ACPI walker = `crates/firmware` (`33§R01`); ns inodes =
// `crates/nscg` (`26§R01`). Re-exports keep call sites stable.
pub use firmware::acpi;
#[cfg(target_os = "oxide-kernel")]
pub use nscg::proc_ns as dev_proc_ns;
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
pub use ::sched::kthread;
#[cfg(target_os = "oxide-kernel")] pub use devfs;
#[cfg(target_os = "oxide-kernel")] pub use security::seccomp;
#[cfg(target_os = "oxide-kernel")] pub use security::bpf as dev_bpf;

/// Kernel-wide heap allocator per `12§2`. Fixed-size BSS heap for v1;
/// replaced by PMM-backed slab routing once a binary stage exists.
/// Hosts the `BTreeMap` / `Vec` machinery used by `vmm::VmaTree` and
/// later subsystems.
///
/// Gated `cfg(target_os = "oxide-kernel")` so the declaration is
/// active only when building for the kernel targets in `targets/`.
/// Host builds (used by hosted tests in this and downstream crates)
/// keep `std`'s default allocator.
#[cfg(target_os = "oxide-kernel")]
#[global_allocator]
static GLOBAL_ALLOC: kalloc::KAlloc = kalloc::KAlloc::new();

// Boot-stub → kernel handoff types now live in `crates/boot-info`
// per the `52§3` shared layer. Re-exported here so existing
// `crate::BootInfo` / `crate::BootMemRegion` / `crate::BootMemKind`
// call sites compile unchanged during the Stage B migration.
pub use boot_info::{BootInfo, BootMemKind, BootMemRegion};

// Module manifest:
// - `entry`: kernel_main orchestration and final handoff.
// - `early`: boot CPU, allocator, memory, and early subsystem bring-up.
// - `runtime`: IRQ, console, SMP, and runtime hook installation.
// - `rootfs`: PCI, mounts, rootfs, keymap, and first-userspace handoff.
// - `hooks`: shared tick and diagnostics hooks used by the boot path.
// - `tests`: crate-local layout checks.
mod kmain {
    pub mod entry;
    pub mod early;
    pub mod hooks;
    pub mod rootfs;
    pub mod runtime;
    #[cfg(test)]
    pub mod tests;
}

pub use kmain::entry::kernel_main;
#[cfg(target_os = "oxide-kernel")] pub use kmain::hooks::{tick_poll_combined, zerotrap_tid};

// Subsystem crates re-exported so `crate::*` call sites resolve.
#[cfg(target_os = "oxide-kernel")] pub use syscalls;
#[cfg(target_os = "oxide-kernel")] pub use procfs;
#[cfg(target_os = "oxide-kernel")] pub use sysfs;
#[cfg(target_os = "oxide-kernel")] pub use cmdline as boot_cmdline;
#[cfg(target_os = "oxide-kernel")] pub use pci_boot;
