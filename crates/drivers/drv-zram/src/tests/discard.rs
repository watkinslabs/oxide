use block::{BlockDevice, BlockRequest};

use crate::Zram;
use crate::state::{Slot, PAGE_BYTES};
use crate::ZRAM_BLOCK_SIZE;

/// One zram PMM page expressed in its fixed logical blocks.
const BLOCKS_PER_PAGE: u32 = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
/// First zram logical block and page index in range fixtures.
const FIRST_BLOCK: u64 = 0;
const FIRST_PAGE_INDEX: usize = 0;
/// Exact page cardinalities exercised by the discard contract.
const ONE_PAGE: usize = 1;
const TWO_PAGES: usize = 2;
const THREE_PAGES: usize = 3;
const FOUR_PAGES: usize = 4;
/// Byte value for initially allocated test buffers.
const ZERO_BYTE: u8 = 0;
/// First nonzero byte in a unique per-page fixture.
const FIRST_PAGE_BYTE: u8 = 0x11;
/// Per-page delta preserves distinct data across a multi-page range.
const PAGE_BYTE_DELTA: u8 = 0x11;
/// One logical block leaves a leading physical-page fragment.
const PARTIAL_BLOCKS: u32 = 1;
/// Full-page discard produces one Linux free notification.
const ONE_NOTIFY_FREE: u64 = 1;
/// Two whole pages in one discard each produce a notification.
const TWO_NOTIFY_FREE: u64 = 2;

fn fixture(page_count: usize) -> (alloc::sync::Arc<Zram>, alloc::vec::Vec<u8>) {
    let zram = Zram::new();
    zram.set_disksize(PAGE_BYTES as u64 * page_count as u64).unwrap();
    let mut bytes = alloc::vec![ZERO_BYTE; PAGE_BYTES * page_count];
    for (page_index, page) in bytes.chunks_exact_mut(PAGE_BYTES).enumerate() {
        page.fill(FIRST_PAGE_BYTE + page_index as u8 * PAGE_BYTE_DELTA);
    }
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, BLOCKS_PER_PAGE * page_count as u32, bytes.clone())).unwrap();
    (zram, bytes)
}

fn read_all(zram: &Zram, page_count: usize) -> alloc::vec::Vec<u8> {
    let mut read = BlockRequest::new_read(FIRST_BLOCK, BLOCKS_PER_PAGE * page_count as u32, ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    read.buffer
}

#[test]
fn partial_discard_skips_the_physical_zram_page() {
    let page_count = ONE_PAGE;
    let (zram, expected) = fixture(page_count);
    let before = zram.stats();
    zram.submit_sync(&mut BlockRequest::new_discard(PARTIAL_BLOCKS as u64, PARTIAL_BLOCKS)).unwrap();
    let after = zram.stats();
    assert_eq!(read_all(&zram, page_count), expected);
    assert!(!matches!(zram.state.lock().slots.get(FIRST_PAGE_INDEX), Some(Slot::Empty)));
    assert_eq!(after.notify_free, before.notify_free);
    assert_eq!(after.orig_data_size, before.orig_data_size);
}

#[test]
fn page_aligned_discard_releases_exact_slot_and_notifies_free() {
    let page_count = TWO_PAGES;
    let (zram, expected) = fixture(page_count);
    zram.submit_sync(&mut BlockRequest::new_discard(BLOCKS_PER_PAGE as u64, BLOCKS_PER_PAGE)).unwrap();
    let mut expected = expected;
    expected[PAGE_BYTES..].fill(ZERO_BYTE);
    let stats = zram.stats();
    assert_eq!(read_all(&zram, page_count), expected);
    assert!(!matches!(zram.state.lock().slots.get(FIRST_PAGE_INDEX), Some(Slot::Empty)));
    assert!(matches!(zram.state.lock().slots.get(ONE_PAGE), Some(Slot::Empty)));
    assert_eq!(stats.notify_free, ONE_NOTIFY_FREE);
    assert_eq!(stats.orig_data_size, PAGE_BYTES as u64);
}

#[test]
fn discard_skips_partial_edges_and_releases_each_full_middle_page() {
    let page_count = FOUR_PAGES;
    let (zram, expected) = fixture(page_count);
    let start = PARTIAL_BLOCKS as u64;
    let length = BLOCKS_PER_PAGE * page_count as u32 - PARTIAL_BLOCKS * TWO_PAGES as u32;
    zram.submit_sync(&mut BlockRequest::new_discard(start, length)).unwrap();
    let mut expected = expected;
    expected[PAGE_BYTES..PAGE_BYTES * THREE_PAGES].fill(ZERO_BYTE);
    let stats = zram.stats();
    assert_eq!(read_all(&zram, page_count), expected);
    let state = zram.state.lock();
    assert!(!matches!(state.slots.get(FIRST_PAGE_INDEX), Some(Slot::Empty)));
    assert!(matches!(state.slots.get(ONE_PAGE), Some(Slot::Empty)));
    assert!(matches!(state.slots.get(TWO_PAGES), Some(Slot::Empty)));
    assert!(!matches!(state.slots.get(FOUR_PAGES - ONE_PAGE), Some(Slot::Empty)));
    drop(state);
    assert_eq!(stats.notify_free, TWO_NOTIFY_FREE);
    assert_eq!(stats.orig_data_size, PAGE_BYTES as u64 * 2);
}
