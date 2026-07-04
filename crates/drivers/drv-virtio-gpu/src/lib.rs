// virtio-gpu driver per `45`. Owns the wire protocol (CTRLQ +
// CURSORQ command-completion ring service), feature negotiation,
// scanout / resource management. Consumed by `47` DRM/KMS for
// userspace UAPI exposure.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

type DeviceKey = virtio::VirtioChildDeviceKey;

mod wire;
pub use wire::*;

mod device;
pub use device::*;

#[cfg(test)]
mod tests;

#[cfg(target_os = "oxide-kernel")]
pub mod post_init;
