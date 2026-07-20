//! zram `backing_dev` path ABI contracts.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use block::{BlockError, MemDisk};
use sync::TaskList;

use super::super::{Zram, ZRAM_BLOCK_SIZE};
use super::super::state::PAGE_BYTES;

/// Unique disk names keep registry fixtures independent under parallel tests.
static BACKING_PATH_TEST_ID: AtomicU32 = AtomicU32::new(0);
/// One backing fixture page is sufficient for selection-only ABI tests.
const BACKING_FIXTURE_BLOCKS: u64 = 1;
/// A zero-capacity block device is invalid Linux backing storage.
const EMPTY_BACKING_FIXTURE_BLOCKS: u64 = 0;

fn register_backing() -> alloc::string::String {
    let id = BACKING_PATH_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let name = alloc::format!("zram-backing-path-{}", id);
    let blocks = PAGE_BYTES as u64 / ZRAM_BLOCK_SIZE as u64 * BACKING_FIXTURE_BLOCKS;
    let disk: Arc<dyn block::BlockDevice> = MemDisk::<TaskList>::new(ZRAM_BLOCK_SIZE, blocks);
    assert_ne!(block::registry::register(&name, disk), 0);
    name
}

fn register_empty_backing() -> alloc::string::String {
    let id = BACKING_PATH_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let name = alloc::format!("zram-backing-empty-{}", id);
    let disk: Arc<dyn block::BlockDevice> = MemDisk::<TaskList>::new(ZRAM_BLOCK_SIZE, EMPTY_BACKING_FIXTURE_BLOCKS);
    assert_ne!(block::registry::register(&name, disk), 0);
    name
}

#[test]
fn backing_dev_accepts_only_dev_path_and_renders_canonical_path() {
    let name = register_backing();
    let path = alloc::format!("/dev/{}", name);
    let zram = Zram::new();
    assert_eq!(zram.set_backing_dev_text(&name), Err(BlockError::Einval));
    assert_eq!(zram.set_backing_dev_text("1:0"), Err(BlockError::Einval));
    zram.set_backing_dev_text(&path).unwrap();
    assert_eq!(zram.backing_dev(), Some(path));
    zram.reset().unwrap();
    assert!(block::registry::unregister(&name));
}

#[test]
fn backing_dev_replaces_uninitialized_disk_and_releases_old_claim() {
    let first = register_backing();
    let second = register_backing();
    let zram = Zram::new();
    zram.set_backing_dev_text(&alloc::format!("/dev/{}", first)).unwrap();
    assert!(block::registry::is_claimed(&first));
    let second_path = alloc::format!("/dev/{}", second);
    zram.set_backing_dev_text(&second_path).unwrap();
    assert!(!block::registry::is_claimed(&first));
    assert!(block::registry::is_claimed(&second));
    assert_eq!(zram.backing_dev(), Some(second_path));
    zram.reset().unwrap();
    assert!(!block::registry::is_claimed(&second));
    assert!(block::registry::unregister(&first));
    assert!(block::registry::unregister(&second));
}

#[test]
fn backing_dev_failure_and_initialized_write_preserve_selection() {
    let name = register_backing();
    let path = alloc::format!("/dev/{}", name);
    let zram = Zram::new();
    zram.set_backing_dev_text(&path).unwrap();
    assert_eq!(zram.set_backing_dev_text("/dev/zram-backing-path-missing"), Err(BlockError::Enxio));
    assert_eq!(zram.backing_dev(), Some(path.clone()));
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    assert_eq!(zram.set_backing_dev_text(&path), Err(BlockError::Ebusy));
    zram.reset().unwrap();
    assert!(block::registry::unregister(&name));
}

#[test]
fn backing_dev_rejects_zero_capacity_disk_with_einval() {
    let name = register_empty_backing();
    let zram = Zram::new();
    assert_eq!(zram.set_backing_dev_text(&alloc::format!("/dev/{}", name)), Err(BlockError::Einval));
    assert!(block::registry::unregister(&name));
}
