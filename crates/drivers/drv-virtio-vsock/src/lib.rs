#![no_std]

extern crate alloc;

mod consts;
mod registry;
mod rx;
mod tx;

pub use consts::{transport_profile, wanted_features, DRIVER_ID, RX_RING_BUFS, VIRTIO_ID_VSOCK};
pub use registry::{
    guest_cid, guest_cid_for, install, present, present_for, raise_rx, rx_drain,
    rx_drain_softirq, shutdown, uninstall, Ctx,
};
pub use tx::tx_packet;

#[cfg(test)]
mod tests;
