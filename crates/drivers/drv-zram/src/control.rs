use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockError, KResult};
use sync::{Spinlock, TaskList};

use crate::Zram;

pub const ZRAM_BLOCK_DRIVER: block::registry::BlockDriver =
    block::registry::BlockDriver::dynamic("zram");
/// Linux `num_devices` module-parameter default.
pub const DEFAULT_NUM_DEVICES: u32 = 1;
/// First zram device index selected by Linux module initialization.
pub const DEFAULT_DEVICE_INDEX: u32 = 0;
/// Linux's default zram block-device name.
pub const DEFAULT_DEVICE_NAME: &str = "zram0";

static DEVICES: Spinlock<Vec<Option<Arc<Zram>>>, TaskList> = Spinlock::new(Vec::new());

fn hot_add_locked(devices: &mut Vec<Option<Arc<Zram>>>) -> KResult<u32> {
    let index = devices.iter().position(Option::is_none).unwrap_or(devices.len()) as u32;
    let extends_table = index as usize == devices.len();
    // Reserve control-table ownership before publishing a registry device, so
    // allocation failure cannot leave an unreachable registered zram disk.
    if extends_table { devices.try_reserve(1).map_err(|_| BlockError::Enomem)?; }
    let device = Zram::new();
    let name = alloc::format!("zram{}", index);
    if block::registry::register_with_driver(ZRAM_BLOCK_DRIVER, &name, None, device.clone()) == 0 {
        return Err(BlockError::Enomem);
    }
    if extends_table { devices.push(Some(device)); }
    else { devices[index as usize] = Some(device); }
    Ok(index)
}

/// Publish Linux's default `zram0` device exactly once. # C: O(num_devices + holes)
pub fn init() -> KResult<()> {
    init_with_num_devices(DEFAULT_NUM_DEVICES)
}

/// Initialize the built-in zram driver with Linux's `num_devices` module
/// parameter value. Zero intentionally publishes no default disks; later
/// zram-control hot_add remains available.
/// # C: O(num_devices + holes)
pub fn init_with_num_devices(num_devices: u32) -> KResult<()> {
    #[cfg(any(test, feature = "hosted"))]
    crate::zsmalloc::install_hosted_test_provider();
    if !crate::page_provider_ready() { return Err(BlockError::Enomem); }
    let mut devices = DEVICES.lock();
    for index in DEFAULT_DEVICE_INDEX..num_devices {
        if devices.get(index as usize).is_none_or(Option::is_none) {
            if hot_add_locked(&mut devices)? != index { return Err(BlockError::Eio); }
        }
    }
    Ok(())
}

/// # C: O(number of holes)
pub fn hot_add() -> KResult<u32> {
    #[cfg(any(test, feature = "hosted"))]
    crate::zsmalloc::install_hosted_test_provider();
    if !crate::page_provider_ready() { return Err(BlockError::Enomem); }
    hot_add_locked(&mut DEVICES.lock())
}

/// # C: O(1)
pub fn hot_remove(index: u32) -> KResult<()> {
    let device = DEVICES.lock().get(index as usize).and_then(|device| device.clone()).ok_or(BlockError::Einval)?;
    let name = alloc::format!("zram{}", index);
    // Linux `zram_remove` freezes block admission before checking its openers
    // and holders, retains that gate through reset, then consumes it in
    // `del_gendisk`. Never hold the zram-control table across reset: its
    // writeback drain may sleep while completing a previously admitted I/O.
    let gate = block::registry::try_quiesce(&name).ok_or(BlockError::Ebusy)?;
    // A configured backing disk is a canonical consumer claim even before
    // disksize initializes zram; release it before removing this control slot.
    device.reset()?;
    device.unregister_movable_owner()?;
    if !gate.unregister() { return Err(BlockError::Eio); }
    let mut devices = DEVICES.lock();
    if !devices.get(index as usize).is_some_and(|current| current.as_ref().is_some_and(|current| Arc::ptr_eq(current, &device))) {
        return Err(BlockError::Eio);
    }
    devices[index as usize] = None;
    Ok(())
}

/// # C: O(1)
pub fn by_index(index: u32) -> Option<Arc<Zram>> {
    DEVICES.lock().get(index as usize).and_then(|device| device.clone())
}

/// # C: O(length of name)
pub fn by_name(name: &str) -> Option<Arc<Zram>> {
    name.strip_prefix("zram")?.parse::<u32>().ok().and_then(by_index)
}

/// Snapshot live device indexes from the canonical zram-control table. This
/// deliberately exposes no second device registry to debugfs consumers.
/// # C: O(number of control slots)
pub fn indices() -> Vec<u32> {
    DEVICES.lock().iter().enumerate().filter_map(|(index, device)| {
        device.as_ref().and_then(|_| u32::try_from(index).ok())
    }).collect()
}

/// PMM shrinker count callback. The device registry lock is released before
/// each zram State lock, so zram compaction cannot invert control ownership.
/// # C: O(devices × zspages squared)
pub fn reclaimable_pages() -> usize {
    let devices: Vec<Arc<Zram>> = DEVICES.lock().iter().flatten().cloned().collect();
    devices.into_iter().fold(0usize, |pages, device| pages.saturating_add(device.reclaimable_pages()))
}

/// PMM shrinker scan callback. Each zram device receives only the remaining
/// budget and releases detached PMM pages outside its State lock.
/// # C: O(devices × zspages cubed)
pub fn reclaim_pages(target: usize) -> usize {
    let devices: Vec<Arc<Zram>> = DEVICES.lock().iter().flatten().cloned().collect();
    let mut released = 0usize;
    for device in devices {
        let Some(remaining) = target.checked_sub(released) else { break; };
        if remaining == 0 { break; }
        released = released.saturating_add(device.reclaim_pages(remaining));
    }
    released
}
