// aarch64 kernel binary stage. Pulls `boot_aarch64::_start` (the
// EDK2/U-Boot entry point) into the link, supplies a panic handler,
// and lets the linker script in `aarch64-kernel.ld` (in this crate) decide
// layout.
//
// `cargo build -p kernel-bin-aarch64 --target ...oxide-kernel.json`
// produces `target/<target>/<profile>/oxide-aarch64`, an ELF64 the
// bootloader can load directly.

#![cfg_attr(target_os = "oxide-kernel", no_std)]
#![cfg_attr(target_os = "oxide-kernel", no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "oxide-kernel")]
extern crate boot_aarch64 as _boot;

/// Panic = halt. v1 inline spin-loop; per-arch `wfi` lands when this
/// shim grows a hal-aarch64 dep.
/// # C: O(infinity)
#[cfg(target_os = "oxide-kernel")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Snapshot the log for whatever is registered to keep it across the
    // reboot — the same call the other architecture's handler makes, so
    // whether a crash leaves a record does not depend on the machine.
    klog::kmsg_dump(klog::kmsg_dump::REASON_PANIC);
    loop { core::hint::spin_loop(); }
}

/// Host-only stub `main` so `cargo test --workspace` can exercise the
/// rest of the workspace without choking on the bin's no_main.
#[cfg(not(target_os = "oxide-kernel"))]
fn main() {}
