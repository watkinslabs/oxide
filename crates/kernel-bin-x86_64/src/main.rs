// x86_64 kernel binary stage. Pulls `boot_x86_64::_start` (the
// Limine entry point) into the link, supplies a panic handler, and
// lets the linker script in `link/x86_64-kernel.ld` decide layout.
//
// `cargo build -p kernel-bin-x86_64 --target ...oxide-kernel.json`
// produces `target/<target>/<profile>/oxide-x86_64`, an ELF64 the
// Limine bootloader can load directly.
//
// On host we still produce a no_main binary that the linker just
// drops into the host toolchain; it has no `_start` of its own and
// is never executed. `cargo check --all-targets` works.

#![cfg_attr(target_os = "oxide-kernel", no_std)]
#![cfg_attr(target_os = "oxide-kernel", no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

// Pull `boot_x86_64::_start` into the link. The `extern crate` form
// (vs `use`) keeps the `_start` symbol live even though no Rust code
// in this crate calls it — Limine reaches it via the ELF entry.
#[cfg(target_os = "oxide-kernel")]
extern crate boot_x86_64 as _boot;

/// Panic = halt. Kernel panics terminate the CPU; the per-arch HAL
/// halt insn is the right floor here, but we don't depend on hal in
/// this thin shim, so an inline loop suffices for v1.
/// # C: O(infinity) — by definition
#[cfg(target_os = "oxide-kernel")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    klog::write_raw(b"\n[PANIC] ");
    if let Some(loc) = info.location() {
        klog::write_raw(loc.file().as_bytes());
        klog::write_raw(b":");
        klog::write_dec_u64(loc.line() as u64);
        klog::write_raw(b": ");
    }
    let msg = info.message().as_str().unwrap_or("(no message)");
    klog::write_raw(msg.as_bytes());
    klog::write_raw(b"\n[PANIC] halted\n");
    loop { core::hint::spin_loop(); }
}

/// Host-only stub `main` so `cargo test --workspace` can exercise the
/// rest of the workspace without choking on the bin's no_main.
#[cfg(not(target_os = "oxide-kernel"))]
fn main() {}
