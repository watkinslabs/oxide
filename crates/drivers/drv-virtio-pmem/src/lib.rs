#![no_std]

extern crate alloc;

mod device;

pub use device::{install, remove, shutdown, transport_profile, DRIVER_ID, VIRTIO_ID_PMEM};
