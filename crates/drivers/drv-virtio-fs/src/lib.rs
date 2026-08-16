// virtiofs — a host directory shared into this guest as a FUSE filesystem
// whose courier is a virtio queue rather than `/dev/fuse`.
//
// Module manifest:
//   * `consts`    — device id, queue layout, buffer geometry.
//   * `config`    — the mount-tag field in the device configuration.
//   * `registry`  — bound devices, their DMA staging buffers, the tag directory.
//   * `transport` — one connection's virtqueue face, implementing the FUSE seam.
//
// The FUSE protocol itself lives in the filesystem crate; nothing here decodes
// a FUSE message beyond the reply length it must bound a copy by.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod consts;
pub mod config;
mod registry;
mod transport;

pub use config::{parse_tag, TagError};
pub use consts::{transport_profile, wanted_features, DRIVER_ID, VIRTIO_ID_FS};
pub use registry::{install, present, request_queue_count, shutdown, tags, uninstall};
pub use transport::VirtioFsTransport;

/// Open the virtiofs device named `tag` as a FUSE transport. `None` when no
/// device carries that tag or a mount already holds it. # C: O(N_devices)
pub fn open_tag(tag: &str) -> Option<fuse_transport::FuseTransportRef> {
    VirtioFsTransport::claim(tag).map(|t| t as fuse_transport::FuseTransportRef)
}

#[cfg(test)]
mod tests;
