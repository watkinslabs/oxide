#![no_std]

extern crate alloc;

mod consts;
mod fill;
mod registry;

pub use consts::{transport_profile, wanted_features, DRIVER_ID, VIRTIO_ID_RNG};
pub use fill::{fill, fill_from_device};
pub use registry::{install, present, shutdown, uninstall};

#[cfg(test)]
mod tests;
