//! Linux zram writeback parser, selection, limit, and backing-space contracts.

use alloc::string::ToString;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use block::{BlockDevice, BlockError, BlockRequest, MemDisk};
use sync::TaskList;

use super::super::{Zram, ZRAM_BLOCK_SIZE, ZRAM_WRITEBACK_ACCOUNTING_BYTES};
use super::super::state::PAGE_BYTES;

/// Independent registry names permit parallel hosted fixtures.
static WRITEBACK_ABI_TEST_ID: AtomicU32 = AtomicU32::new(0);
/// First block of the zram device.
const FIRST_BLOCK: u64 = 0;
/// The second zram page starts after exactly one PMM page of blocks.
const SECOND_PAGE: u64 = PAGE_BYTES as u64 / ZRAM_BLOCK_SIZE as u64;
/// A fixture needs two resident slots to exhaust one backing extent.
const TWO_ZRAM_PAGES: u64 = 2;
/// Exactly one physical backing page forces Linux's ENOSPC path.
const ONE_BACKING_PAGE: u64 = 1;
/// Deterministic non-SAME payload seed and xorshift shifts.
const RANDOM_SEED: u32 = 0x9e37_79b9;
const RANDOM_LEFT_A: u32 = 13;
const RANDOM_RIGHT: u32 = 17;
const RANDOM_LEFT_B: u32 = 5;
/// Linux writeback ABI command forms.
const LEGACY_IDLE: &str = "idle";
const TYPE_IDLE: &str = "type=idle";
const PAGE_INDEX_ZERO: &str = "page_index=0";
const PAGE_INDEXES_ZERO: &str = "page_indexes=0-0";
const NON_LINUX_ALL: &str = "all";
const INVALID_SINGULAR_RANGE: &str = "page_index=0-0";
const INVALID_PLURAL_SINGLE: &str = "page_indexes=0";
const EMPTY_NAMED_FIELD: &str = "future=";
const EMPTY_NAMED_KEY: &str = "=future";
/// Three page-budget units exercises round-down independent of host page size.
const THREE_PAGE_BUDGETS: u64 = 3;

fn random_page() -> alloc::vec::Vec<u8> {
    let mut state = RANDOM_SEED;
    let mut page = alloc::vec![0; PAGE_BYTES];
    for byte in &mut page {
        state ^= state << RANDOM_LEFT_A;
        state ^= state >> RANDOM_RIGHT;
        state ^= state << RANDOM_LEFT_B;
        *byte = state as u8;
    }
    page
}

fn register_backing(pages: u64) -> alloc::string::String {
    let id = WRITEBACK_ABI_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let name = alloc::format!("zram-writeback-abi-{}", id);
    let blocks = pages * PAGE_BYTES as u64 / ZRAM_BLOCK_SIZE as u64;
    let disk: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(ZRAM_BLOCK_SIZE, blocks);
    assert_ne!(block::registry::register(&name, disk), 0);
    name
}

fn zram_with_backing(pages: u64, backing_pages: u64) -> (Arc<Zram>, alloc::string::String) {
    let name = register_backing(backing_pages);
    let zram = Zram::new();
    zram.set_backing_dev_text(&alloc::format!("/dev/{}", name)).unwrap();
    zram.set_disksize(pages * PAGE_BYTES as u64).unwrap();
    (zram, name)
}

fn cleanup(zram: Arc<Zram>, name: &str) {
    zram.reset().unwrap();
    assert!(block::registry::unregister(name));
}

#[test]
fn writeback_parser_accepts_linux_forms_and_rejects_non_linux_all() {
    let (zram, name) = zram_with_backing(1, ONE_BACKING_PAGE);
    assert_eq!(zram.writeback_text(NON_LINUX_ALL), Err(BlockError::Einval));
    assert_eq!(zram.writeback_text(INVALID_SINGULAR_RANGE), Err(BlockError::Einval));
    assert_eq!(zram.writeback_text(INVALID_PLURAL_SINGLE), Err(BlockError::Einval));
    assert_eq!(zram.writeback_text(EMPTY_NAMED_FIELD), Err(BlockError::Einval));
    assert_eq!(zram.writeback_text(EMPTY_NAMED_KEY), Err(BlockError::Einval));
    assert_eq!(zram.writeback_text(LEGACY_IDLE), Ok(()));
    assert_eq!(zram.writeback_text(TYPE_IDLE), Ok(()));
    assert_eq!(zram.writeback_text(PAGE_INDEX_ZERO), Ok(()));
    assert_eq!(zram.writeback_text(PAGE_INDEXES_ZERO), Ok(()));
    cleanup(zram, &name);
}

#[test]
fn same_slots_are_excluded_from_every_writeback_form() {
    let (zram, name) = zram_with_backing(1, ONE_BACKING_PAGE);
    let blocks = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, blocks, alloc::vec![0; PAGE_BYTES])).unwrap();
    zram.mark_idle_text("all").unwrap();
    for command in [LEGACY_IDLE, TYPE_IDLE, "huge", "type=huge", "huge_idle", "type=huge_idle", "incompressible", "type=incompressible", PAGE_INDEX_ZERO, PAGE_INDEXES_ZERO] {
        assert_eq!(zram.writeback_text(command), Ok(()));
        assert_eq!(zram.stats().backing_pages, 0);
    }
    cleanup(zram, &name);
}

#[test]
fn backing_extent_exhaustion_returns_linux_enospc() {
    let (zram, name) = zram_with_backing(TWO_ZRAM_PAGES, ONE_BACKING_PAGE);
    let blocks = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, blocks, random_page())).unwrap();
    zram.submit_sync(&mut BlockRequest::new_write(SECOND_PAGE, blocks, random_page())).unwrap();
    assert_eq!(zram.writeback_text("page_indexes=0-1"), Err(BlockError::Enospc));
    assert_eq!(zram.stats().backing_pages, ONE_BACKING_PAGE);
    cleanup(zram, &name);
}

#[test]
fn writeback_limit_rounds_down_to_whole_zram_pages() {
    let zram = Zram::new();
    let units = PAGE_BYTES as u64 / ZRAM_WRITEBACK_ACCOUNTING_BYTES;
    let unaligned = THREE_PAGE_BUDGETS * units + units - 1;
    zram.set_writeback_limit_text(&unaligned.to_string()).unwrap();
    assert_eq!(zram.stats().writeback_limit, THREE_PAGE_BUDGETS * units);
}
