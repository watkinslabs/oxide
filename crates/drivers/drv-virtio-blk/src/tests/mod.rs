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

// The block registry's INDEX space and the driver device model are
// process-global. `TEST_DISK_SEQ` keeps each test's disk NAME unique, but not
// its index: `register` hands out the lowest free index, so a sibling
// registering while this test is between `remove_blk` and its
// `by_dev(dev_t).is_none()` check takes the number this test just freed and
// answers that lookup with the sibling's disk. Every test that publishes into
// either registry takes this claim. Poison is recovered: one failing test must
// report as one failure, not cascade into every sibling.
static BLOCK_MODEL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn claim_block_model() -> std::sync::MutexGuard<'static, ()> {
    BLOCK_MODEL.lock().unwrap_or_else(|e| e.into_inner())
}

fn child_key(bus: u8, device: u8, function: u8) -> VirtioChildDeviceKey {
    VirtioChildDeviceKey::from_raw(
        ((bus as u32) << 16) | ((device as u32) << 8) | function as u32,
    )
}
