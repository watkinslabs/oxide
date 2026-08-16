// virtio-9p — the transport a hypervisor exports a host directory over.
//
// Module manifest:
//   * `consts`    — device id, feature bits, buffer geometry.
//   * `config`    — the mount-tag field in the device configuration.
//   * `registry`  — bound devices, their DMA staging buffers, the tag directory.
//   * `transport` — one session's virtqueue face, implementing `ninep::Transport`.
//   * `factory`   — publishing `trans=virtio` into the 9P transport directory.
//
// The protocol itself lives in `ninep`; nothing here decodes a 9P message.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod consts;
pub mod config;
mod registry;
mod transport;
mod factory;

pub use config::{parse_tag, TagError};
pub use consts::{transport_profile, wanted_features, DRIVER_ID, VIRTIO_ID_9P, VIRTIO_9P_F_MOUNT_TAG};
pub use registry::{install, present, shutdown, tags, uninstall};
pub use transport::Virtio9pTransport;
pub use factory::{open_tag, register_transport, unregister_transport};

#[cfg(test)]
mod tests;
