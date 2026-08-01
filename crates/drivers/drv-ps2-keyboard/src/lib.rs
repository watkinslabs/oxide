#![no_std]
//! Real i8042 PS/2 keyboard driver (drivers-plan D3.4). x86_64 ONLY —
//! on aarch64 every entry point is an empty no-op so the workspace builds
//! and the arm boot is untouched (there is no i8042 on `qemu virt`).
//!
//! Pipeline: i8042 controller bring-up + keyboard reset/identify, then a
//! Scancode-Set-1 decoder that turns make/break codes (incl. 0xE0-prefixed
//! extended keys) into `(linux_keycode, pressed)` and feeds each through
//! the ONE shared input pipeline `drv_virtio_input::drain::handle_key_event`
//! — the same modifier / Ctrl-Alt-F<n> VT-switch / Shift-PgUp scrollback /
//! keymap→byte logic the virtio-input keyboard uses. No duplicate key logic.
//!
//! Input delivery is IRQ1-owned by the i8042 driver. `probe()` programs the
//! I/O APIC redirection entry and enables the controller IRQ bit only after the
//! handler is installed; `remove()` disables scanning/IRQ delivery, masks the
//! line, frees the vector, and clears driver state.
//!
//! Module manifest:
//! * `scancode` — pure Scancode-Set-1 decoder; host-testable, no device access.
//! * `noop` — off-target shell (aarch64, host test builds): every entry point
//!   an empty fn so the workspace member always builds.
//! * `imp` — the real device, x86_64 kernel target only.

// The real device + the bridge into the kernel input pipeline only exist
// on the kernel x86 target; host builds (hosted `cargo test` for the pure
// scancode decoder) and aarch64 use the no-op shell. Keeping the gate on
// `oxide-kernel` (not just `x86_64`) lets the scancode unit tests run on
// the dev host without dragging in the `oxide-kernel`-gated kernel crates.
//
// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]

// The pure Scancode-Set-1 decoder is host-testable (x86_64 host or kernel).
#[cfg(target_arch = "x86_64")]
mod scancode;

#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
#[path = "noop.rs"]
mod imp;

// `debug_boot!` is `#[macro_export]`ed by kmacros (gated on its
// `debug-boot` feature); pull it into crate scope for the real imp.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[macro_use]
extern crate kmacros;
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern crate alloc;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[path = "imp/mod.rs"]
mod imp;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub use imp::{configure_probe, driver};
pub use imp::present;
