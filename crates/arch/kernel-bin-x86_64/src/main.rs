// x86_64 kernel binary stage. Pulls `boot_x86_64::_start` (the
// multiboot2 trampoline's continuation) into the link, supplies a
// panic handler, and
// lets the linker script in `x86_64-kernel.ld` (in this crate) decide layout.
//
// `cargo build -p kernel-bin-x86_64 --target ...oxide-kernel.json`
// produces `target/<target>/<profile>/oxide-x86_64`, an ELF64 the
// GRUB can load directly via multiboot2.
//
// On host we still produce a no_main binary that the linker just
// drops into the host toolchain; it has no `_start` of its own and
// is never executed. `cargo check --all-targets` works.

#![cfg_attr(target_os = "oxide-kernel", no_std)]
#![cfg_attr(target_os = "oxide-kernel", no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

// Pull `boot_x86_64::_start` into the link. The `extern crate` form
// (vs `use`) keeps the `_start` symbol live even though no Rust code
// in this crate calls it — the multiboot2 trampoline tail-calls it.
#[cfg(target_os = "oxide-kernel")]
extern crate boot_x86_64 as _boot;

/// Panic. Reports through the emergency console route — non-allocating, never
/// `write_raw` — then does what the boot line's `panic=` asked: stop with the
/// text on screen, or restart the machine after a delay. A panicking allocator
/// call must not have this handler recurse into the same allocator through a
/// framebuffer-scroll fan-out that can itself allocate; that recursion
/// self-deadlocks on this CPU's own held lock, producing a silent hang with no
/// panic text at all.
/// # C: O(infinity) — by definition
#[cfg(target_os = "oxide-kernel")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! { klog::oops::panic_and_stop(info) }

/// Host-only stub `main` so `cargo test --workspace` can exercise the
/// rest of the workspace without choking on the bin's no_main.
#[cfg(not(target_os = "oxide-kernel"))]
fn main() {}
