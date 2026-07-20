use block::{BlockDevice, BlockRequest, MemDisk};
use core::sync::atomic::{AtomicU32, Ordering};
use sync::TaskList;
use crate::{by_index, hot_add, hot_remove, Zram, ZRAM_BLOCK_SIZE};
use crate::state::{BackingFormat, Compression, Slot, PAGE_BYTES};
// Module manifest:
// - control: default-device and zram-control lifecycle tests.
// - lifecycle: initialized-action and writeback-batch ABI guards.
// - backing: path-only backing-device selection and replacement contracts.
// - writeback_abi: Linux writeback parser, selection, limits, and ENOSPC tests.
// - discard: full-page discard range and free-stat contracts.
mod control;
mod lifecycle;
mod writeback_abi;
mod backing;
mod compression;
mod discard;
mod basic;
/// Block zero for complete-device test I/O.
const FIRST_DEVICE_BLOCK: u64 = 0;
/// Fresh-byte value for zeroed device data and assertions.
const ZERO_DATA_BYTE: u8 = 0;
/// Distinct page halves verify that a partial zram discard leaves both intact.
const WRITE_ZEROES_FIRST_HALF_BYTE: u8 = 0x3c;
const WRITE_ZEROES_SECOND_HALF_BYTE: u8 = 0xa5;
/// First observed compressed-slot allocation has nonzero memory use.
const EMPTY_MEMORY_USAGE: u64 = 0;
/// zsmalloc stores compressed objects in class-selected multi-page zspages.
const MINIMUM_NONZERO_MEMORY_USAGE: u64 = 1;
/// One logical zram page, used by byte-valued zram configuration contracts.
const ZRAM_PAGE_BYTES: u64 = PAGE_BYTES as u64;
/// A nonzero limit below one stored zram object forces allocation rejection.
const IMPOSSIBLE_MEMORY_LIMIT_BYTES: u64 = 1;
/// A successful final swap-slot notification is counted once.
const ONE_SLOT_NOTIFICATION: u64 = 1;
/// Binary-unit sysfs fixture and its byte count.
const ONE_MEBIBYTE_TEXT: &str = "1M";
const TWO_MEBIBYTE_TEXT: &str = "2M";
/// Fresh GNOME QEMU's zram-generator config resolves `min(ram, 8192)` to 4 GiB.
const GENERATOR_DISKSIZE_TEXT: &str = "4G";
const KIB_BYTES: u64 = 1024;
const MEBIBYTE_BYTES: u64 = KIB_BYTES * KIB_BYTES;
const GIBIBYTE_BYTES: u64 = MEBIBYTE_BYTES * KIB_BYTES;
const GENERATOR_DISKSIZE_GIB: u64 = 4;
const TWO_MEBIBYTES: u64 = 2;
/// zsmalloc fixture class with four objects per one-page zspage.
const COMPACTION_OBJECT_BYTES: usize = PAGE_BYTES / 4;
/// Distinct payloads prove handle rewrites preserve both live objects.
const COMPACTION_FIRST_BYTE: u8 = 0x31;
const COMPACTION_LAST_BYTE: u8 = 0x73;
const COMPACTION_OBJECT_COUNT: usize = 9;
const COMPACTION_FREED_INDEX: usize = 0;
const COMPACTION_FIRST_LIVE_INDEX: usize = 1;
const COMPACTION_LAST_INDEX: usize = COMPACTION_OBJECT_COUNT - 1;
const COMPACTION_INITIAL_PAGE_COUNT: usize = 3;
const COMPACTION_FINAL_PAGE_COUNT: usize = 2;
/// A compaction fixture frees exactly one fragmented backing page.
const COMPACTION_RELEASED_PAGE_COUNT: u64 = 1;
/// Backing-disk block size; it divides the zram PMM page size exactly.
const BACKING_BLOCK_SIZE: u32 = ZRAM_BLOCK_SIZE;
/// Two zram pages make a compact backing-disk test fixture.
const BACKING_PAGE_COUNT: u64 = 2;
/// Xorshift32 seed and shifts for an incompressible hosted fixture.
const INCOMPRESSIBLE_SEED: u32 = 0x9e37_79b9;
const XORSHIFT_LEFT_A: u32 = 13;
const XORSHIFT_RIGHT: u32 = 17;
const XORSHIFT_LEFT_B: u32 = 5;
/// No remaining pages in the writeback-budget rejection case.
const NO_WRITEBACK_BUDGET: &str = "0";
/// One Linux 4 KiB writeback accounting unit allowed by the success case.
const ONE_WRITEBACK_ACCOUNTING_UNIT: &str = "1";
/// Distinct page fills make a range writeback test detect skipped pages.
const FIRST_RANGE_PAGE_BYTE: u8 = 1;
const SECOND_RANGE_PAGE_BYTE: u8 = 2;
/// Linux range-form writeback request for both pages in this fixture.
const FIRST_TWO_PAGE_RANGE_REQUEST: &str = "page_indexes=0-1";
/// Linux compressed-writeback sysfs boolean text.
const ENABLED_TEXT: &str = "1";
/// Linux `kstrtobool` spelling accepted by compressed writeback configuration.
const ENABLED_BOOLEAN_TEXT: &str = "yes";
/// Any nonzero numeric write enables Linux writeback-limit enforcement.
const ENABLED_WRITEBACK_LIMIT_TEXT: &str = "2";
/// Secondary LZ4 compressor selected for Linux priority one recompression.
const RECOMP_LZ4_PRIORITY_ONE: &str = "algo=lz4 priority=1";
/// Deflate primary compressor used to establish a less compact source object.
const DEFLATE_ALGORITHM_TEXT: &str = "deflate";
/// One eligible page, no encoded-size threshold, at priority one.
const RECOMPRESS_ONE_PAGE: &str = "priority=1 threshold=0 max_pages=1";
/// Linux name-selected form for the configured secondary compressor.
const RECOMPRESS_LZ4_ONE_PAGE: &str = "algo=lz4 threshold=0 max_pages=1";
/// Linux age-form idle request: zero seconds selects every allocated slot.
const IDLE_ZERO_SECONDS: &str = "0";
/// Linux request that marks all eligible zram objects idle.
const IDLE_ALL: &str = "all";

/// Linux writeback selector for idle resident objects.
const WRITEBACK_IDLE: &str = "idle";
/// Unique registry name suffix for parallel hosted tests.
static BACKING_TEST_ID: AtomicU32 = AtomicU32::new(0);
mod foundation;

#[test]
fn initialized_device_rejects_reconfiguration() {
    let zram = Zram::new();
    zram.set_disksize_text(ONE_MEBIBYTE_TEXT).unwrap();
    assert_eq!(zram.set_disksize_text(TWO_MEBIBYTE_TEXT), Err(block::BlockError::Ebusy));
    assert_eq!(zram.set_algorithm_text(crate::ZRAM_COMP_ALGORITHM), Err(block::BlockError::Ebusy));
}

#[test]
fn final_swap_reference_releases_compressed_slot() {
    let zram = Zram::new();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let mut data = alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES];
    for (index, byte) in data.iter_mut().enumerate() { *byte = index as u8; }
    let blocks = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_DEVICE_BLOCK, blocks, data)).unwrap();
    assert_ne!(zram.stats().mem_used, EMPTY_MEMORY_USAGE);
    zram.swap_slot_free_notify(FIRST_DEVICE_BLOCK, blocks).unwrap();
    let stats = zram.stats();
    assert_eq!(stats.mem_used, EMPTY_MEMORY_USAGE);
    assert_eq!(stats.notify_free, ONE_SLOT_NOTIFICATION);
    let mut read = BlockRequest::new_read(FIRST_DEVICE_BLOCK, blocks, ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert_eq!(read.buffer, alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES]);
}

#[test]
fn discard_of_a_full_page_releases_storage_and_updates_notify_free() {
    let zram = Zram::new();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let blocks = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
    let mut data = alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES];
    for (index, byte) in data.iter_mut().enumerate() { *byte = index as u8; }
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_DEVICE_BLOCK, blocks, data)).unwrap();
    zram.submit_sync(&mut BlockRequest::new_discard(FIRST_DEVICE_BLOCK, blocks)).unwrap();
    let stats = zram.stats();
    assert_eq!(stats.mem_used, EMPTY_MEMORY_USAGE);
    assert_eq!(stats.notify_free, ONE_SLOT_NOTIFICATION);
}

#[test]
fn rejected_write_releases_its_new_pool_object() {
    let zram = Zram::new();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let blocks = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
    let mut first = alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES];
    let mut second = alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES];
    let mut random = INCOMPRESSIBLE_SEED;
    for (first_byte, second_byte) in first.iter_mut().zip(&mut second) {
        random ^= random << XORSHIFT_LEFT_A;
        random ^= random >> XORSHIFT_RIGHT;
        random ^= random << XORSHIFT_LEFT_B;
        *first_byte = random as u8;
        *second_byte = !*first_byte;
    }
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_DEVICE_BLOCK, blocks, first)).unwrap();
    let used = zram.stats().mem_used;
    zram.set_mem_limit(IMPOSSIBLE_MEMORY_LIMIT_BYTES).unwrap();
    assert_eq!(zram.submit_sync(&mut BlockRequest::new_write(FIRST_DEVICE_BLOCK, blocks, second)), Err(block::BlockError::Enomem));
    assert_eq!(zram.stats().mem_used, used);
    zram.compact().unwrap();
    assert_eq!(zram.state.lock().pool.page_count(), COMPACTION_RELEASED_PAGE_COUNT as usize);
}

#[test]
fn control_reuses_removed_index() {
    let index = hot_add().unwrap();
    assert!(by_index(index).is_some());
    assert!(hot_remove(index).is_ok());
    assert!(by_index(index).is_none());
    assert_eq!(hot_add().unwrap(), index);
    assert!(hot_remove(index).is_ok());
}

#[test]
fn control_removes_initialized_unused_device() {
    let index = hot_add().unwrap();
    let device = by_index(index).unwrap();
    device.set_disksize(PAGE_BYTES as u64).unwrap();
    assert!(hot_remove(index).is_ok());
    assert!(by_index(index).is_none());
}

#[test]
fn writeback_roundtrips_through_claimed_backing_disk() {
    let test_id = BACKING_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let name = alloc::format!("zram-backing-test{}", test_id);
    let blocks_per_page = PAGE_BYTES as u64 / BACKING_BLOCK_SIZE as u64;
    let backing = MemDisk::<TaskList>::new(BACKING_BLOCK_SIZE, BACKING_PAGE_COUNT * blocks_per_page);
    assert_ne!(block::registry::register(&name, backing), 0);
    let zram = Zram::new();
    let dev = alloc::format!("/dev/{}", name);
    zram.set_backing_dev_text(&dev).unwrap();
    assert!(block::registry::is_claimed(&name));
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let mut data = alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES];
    for (index, byte) in data.iter_mut().enumerate() { *byte = index as u8; }
    let blocks = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_DEVICE_BLOCK, blocks, data.clone())).unwrap();
    assert_ne!(zram.stats().mem_used, EMPTY_MEMORY_USAGE);
    zram.writeback_all().unwrap();
    assert_eq!(zram.stats().mem_used, EMPTY_MEMORY_USAGE);
    let mut read = BlockRequest::new_read(FIRST_DEVICE_BLOCK, blocks, ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert_eq!(read.buffer, data);
    zram.reset().unwrap();
    assert!(!block::registry::is_claimed(&name));
    assert!(block::registry::unregister(&name));
}

#[test]
fn idle_and_huge_selectors_write_only_matching_slots() {
    let test_id = BACKING_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let name = alloc::format!("zram-selector-test{}", test_id);
    let blocks_per_page = PAGE_BYTES as u64 / BACKING_BLOCK_SIZE as u64;
    let backing = MemDisk::<TaskList>::new(BACKING_BLOCK_SIZE, BACKING_PAGE_COUNT * blocks_per_page);
    assert_ne!(block::registry::register(&name, backing), 0);
    let disk = block::registry::by_name(&name).unwrap();
    let zram = Zram::new();
    zram.set_backing_dev_text(&alloc::format!("/dev/{}", name)).unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let mut data = alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES];
    let mut random = INCOMPRESSIBLE_SEED;
    for byte in &mut data {
        random ^= random << XORSHIFT_LEFT_A;
        random ^= random >> XORSHIFT_RIGHT;
        random ^= random << XORSHIFT_LEFT_B;
        *byte = random as u8;
    }
    let blocks = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_DEVICE_BLOCK, blocks, data.clone())).unwrap();
    assert_ne!(zram.stats().huge_pages, EMPTY_MEMORY_USAGE);
    zram.writeback_text("huge_idle").unwrap();
    assert_ne!(zram.stats().mem_used, EMPTY_MEMORY_USAGE);
    zram.mark_idle_text(IDLE_ZERO_SECONDS).unwrap();
    zram.writeback_text("huge_idle").unwrap();
    assert_eq!(zram.stats().mem_used, EMPTY_MEMORY_USAGE);
    let mut read = BlockRequest::new_read(FIRST_DEVICE_BLOCK, blocks, ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert_eq!(read.buffer, data);
    zram.reset().unwrap();
    assert!(!block::registry::is_claimed(&name));
    assert!(block::registry::unregister(&disk.name));
}

#[test]
fn idle_writeback_excludes_same_filled_pages() {
    let test_id = BACKING_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let name = alloc::format!("zram-idle-same-test{}", test_id);
    let blocks_per_page = PAGE_BYTES as u64 / BACKING_BLOCK_SIZE as u64;
    let backing = MemDisk::<TaskList>::new(BACKING_BLOCK_SIZE, BACKING_PAGE_COUNT * blocks_per_page);
    assert_ne!(block::registry::register(&name, backing), 0);
    let zram = Zram::new();
    zram.set_backing_dev_text(&alloc::format!("/dev/{}", name)).unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let blocks = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_DEVICE_BLOCK, blocks, alloc::vec![FIRST_RANGE_PAGE_BYTE; PAGE_BYTES])).unwrap();
    zram.mark_idle_text(IDLE_ALL).unwrap();
    zram.writeback_text(WRITEBACK_IDLE).unwrap();
    assert_eq!(zram.stats().backing_pages, EMPTY_MEMORY_USAGE);
    zram.reset().unwrap();
    assert!(block::registry::unregister(&name));
}

#[test]
fn writeback_limit_rejects_then_accounts_one_page() {
    let test_id = BACKING_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let name = alloc::format!("zram-limit-test{}", test_id);
    let blocks_per_page = PAGE_BYTES as u64 / BACKING_BLOCK_SIZE as u64;
    let backing = MemDisk::<TaskList>::new(BACKING_BLOCK_SIZE, BACKING_PAGE_COUNT * blocks_per_page);
    assert_ne!(block::registry::register(&name, backing), 0);
    let zram = Zram::new();
    zram.set_backing_dev_text(&alloc::format!("/dev/{}", name)).unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let mut data = alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES];
    for (index, byte) in data.iter_mut().enumerate() { *byte = index as u8; }
    let blocks = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_DEVICE_BLOCK, blocks, data)).unwrap();
    zram.set_writeback_limit_enable_text(ONE_WRITEBACK_ACCOUNTING_UNIT).unwrap();
    zram.set_writeback_limit_text(NO_WRITEBACK_BUDGET).unwrap();
    assert_eq!(zram.writeback_page_index(FIRST_DEVICE_BLOCK), Err(block::BlockError::Eio));
    zram.set_writeback_limit_text(ONE_WRITEBACK_ACCOUNTING_UNIT).unwrap();
    zram.writeback_page_index(FIRST_DEVICE_BLOCK).unwrap();
    let stats = zram.stats();
    assert_eq!(stats.writeback_limit, 0);
    assert_eq!(stats.backing_writes, 1);
    assert_eq!(stats.backing_pages, 1);
    zram.reset().unwrap();
    assert!(block::registry::unregister(&name));
}

#[test]
fn hot_remove_releases_uninitialized_backing_claim() {
    let test_id = BACKING_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let name = alloc::format!("zram-remove-backing{}", test_id);
    let blocks_per_page = PAGE_BYTES as u64 / BACKING_BLOCK_SIZE as u64;
    let backing = MemDisk::<TaskList>::new(BACKING_BLOCK_SIZE, BACKING_PAGE_COUNT * blocks_per_page);
    assert_ne!(block::registry::register(&name, backing), 0);
    let index = hot_add().unwrap();
    let zram = by_index(index).unwrap();
    zram.set_backing_dev_text(&alloc::format!("/dev/{}", name)).unwrap();
    assert!(block::registry::is_claimed(&name));
    hot_remove(index).unwrap();
    assert!(!block::registry::is_claimed(&name));
    assert!(block::registry::unregister(&name));
}

#[test]
fn writeback_page_indexes_range_persists_each_selected_page() {
    let test_id = BACKING_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let name = alloc::format!("zram-range-test{}", test_id);
    let blocks_per_page = PAGE_BYTES as u64 / BACKING_BLOCK_SIZE as u64;
    let backing = MemDisk::<TaskList>::new(BACKING_BLOCK_SIZE, BACKING_PAGE_COUNT * blocks_per_page);
    assert_ne!(block::registry::register(&name, backing), 0);
    let zram = Zram::new();
    zram.set_backing_dev_text(&alloc::format!("/dev/{}", name)).unwrap();
    zram.set_disksize(PAGE_BYTES as u64 * BACKING_PAGE_COUNT).unwrap();
    let blocks = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
    let mut first = alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES];
    let mut second = alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES];
    for (index, (first_byte, second_byte)) in first.iter_mut().zip(&mut second).enumerate() {
        *first_byte = FIRST_RANGE_PAGE_BYTE.wrapping_add(index as u8);
        *second_byte = SECOND_RANGE_PAGE_BYTE.wrapping_sub(index as u8);
    }
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_DEVICE_BLOCK, blocks, first)).unwrap();
    zram.submit_sync(&mut BlockRequest::new_write(blocks as u64, blocks, second)).unwrap();
    zram.writeback_text(FIRST_TWO_PAGE_RANGE_REQUEST).unwrap();
    assert_eq!(zram.stats().backing_pages, BACKING_PAGE_COUNT);
    zram.reset().unwrap();
    assert!(block::registry::unregister(&name));
}

#[test]
fn compressed_writeback_preserves_packed_slot_and_roundtrips() {
    let test_id = BACKING_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let name = alloc::format!("zram-compressed-wb{}", test_id);
    let blocks_per_page = PAGE_BYTES as u64 / BACKING_BLOCK_SIZE as u64;
    let backing = MemDisk::<TaskList>::new(BACKING_BLOCK_SIZE, BACKING_PAGE_COUNT * blocks_per_page);
    assert_ne!(block::registry::register(&name, backing), 0);
    let zram = Zram::new();
    zram.set_backing_dev_text(&alloc::format!("/dev/{}", name)).unwrap();
    zram.set_compressed_writeback_text(ENABLED_TEXT).unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let mut data = alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES];
    for (index, byte) in data.iter_mut().enumerate() { *byte = (index % u8::MAX as usize) as u8; }
    let blocks = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_DEVICE_BLOCK, blocks, data.clone())).unwrap();
    zram.writeback_page_index(FIRST_DEVICE_BLOCK).unwrap();
    assert!(matches!(zram.state.lock().slots.get(0), Some(Slot::Backed { format: BackingFormat::Packed { .. }, .. })));
    let mut read = BlockRequest::new_read(FIRST_DEVICE_BLOCK, blocks, ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert_eq!(read.buffer, data);
    zram.reset().unwrap();
    assert!(block::registry::unregister(&name));
}

#[test]
fn recompress_replaces_larger_secondary_object_with_selected_algorithm() {
    let zram = Zram::new();
    zram.set_algorithm_text(DEFLATE_ALGORITHM_TEXT).unwrap();
    zram.set_recomp_algorithm_text(RECOMP_LZ4_PRIORITY_ONE).unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let mut data = alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES];
    for (index, byte) in data.iter_mut().enumerate() { *byte = (index % u8::MAX as usize) as u8; }
    let blocks = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_DEVICE_BLOCK, blocks, data.clone())).unwrap();
    let before = zram.stats();
    zram.recompress_text(RECOMPRESS_ONE_PAGE).unwrap();
    assert!(matches!(zram.state.lock().slots.get(0), Some(Slot::Packed { algorithm: Compression::Lz4, .. })));
    let after = zram.stats();
    assert!(after.mem_used <= before.mem_used);
    assert!(after.compr_data_size < before.compr_data_size);
    let mut read = BlockRequest::new_read(FIRST_DEVICE_BLOCK, blocks, ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert_eq!(read.buffer, data);
}

#[test]
fn recompress_selects_configured_secondary_by_algorithm_name() {
    let zram = Zram::new();
    zram.set_algorithm_text(DEFLATE_ALGORITHM_TEXT).unwrap();
    zram.set_recomp_algorithm_text(RECOMP_LZ4_PRIORITY_ONE).unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let mut data = alloc::vec![ZERO_DATA_BYTE; PAGE_BYTES];
    for (index, byte) in data.iter_mut().enumerate() { *byte = (index % u8::MAX as usize) as u8; }
    let blocks = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_DEVICE_BLOCK, blocks, data)).unwrap();
    zram.recompress_text(RECOMPRESS_LZ4_ONE_PAGE).unwrap();
    assert!(matches!(zram.state.lock().slots.get(0), Some(Slot::Packed { algorithm: Compression::Lz4, .. })));
}

#[test]
fn writeback_controls_accept_linux_boolean_and_nonzero_forms() {
    let zram = Zram::new();
    zram.set_compressed_writeback_text(ENABLED_BOOLEAN_TEXT).unwrap();
    assert!(zram.compressed_writeback());
    zram.set_writeback_limit_enable_text(ENABLED_WRITEBACK_LIMIT_TEXT).unwrap();
    assert!(zram.stats().writeback_limit_enable);
}
