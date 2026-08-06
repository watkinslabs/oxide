//! Firmware linear-framebuffer platform driver.
//!
//! Module manifest:
//! - `format`: packed-RGB validation, fbdev metadata, and damage conversion.
//! - `driver`: platform-device probe/remove, WC mapping, fbdev/fbcon lifetime.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod driver;
mod format;

pub use driver::{configure_probe, device_addr, driver, present};
