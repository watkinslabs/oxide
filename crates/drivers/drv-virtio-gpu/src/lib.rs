// virtio-gpu driver per `45`. Owns the wire protocol (CTRLQ +
// CURSORQ command-completion ring service), feature negotiation,
// scanout / resource management. Consumed by `47` DRM/KMS for
// userspace UAPI exposure.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod wire;
pub use wire::*;

mod edid;
pub use edid::*;

mod device;
pub use device::*;

#[cfg(test)]
mod tests;

#[cfg(any(target_os = "oxide-kernel", test))]
pub mod post_init;
