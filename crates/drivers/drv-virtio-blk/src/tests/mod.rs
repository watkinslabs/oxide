use std::format;
use std::string::String;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::vec;
use std::vec::Vec;

use block::{BlockDevice, BlockError, BlockRequest};
use virtio::blk;
use virtio::queue::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
use virtio::VirtioChildDeviceKey;

mod chain;
mod chunking;
mod config;
mod helpers;
mod lifecycle;
mod lost_wakeup;
mod naming;

static TEST_DISK_SEQ: AtomicUsize = AtomicUsize::new(0);

fn child_key(bus: u8, device: u8, function: u8) -> VirtioChildDeviceKey {
    VirtioChildDeviceKey::from_raw(
        ((bus as u32) << 16) | ((device as u32) << 8) | function as u32,
    )
}
