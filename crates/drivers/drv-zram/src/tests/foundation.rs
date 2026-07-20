use block::{BlockDevice, BlockRequest};

use crate::{Zram, ZRAM_BLOCK_SIZE};
use crate::state::PAGE_BYTES;

/// First zram block in a complete-page fixture.
const FIRST_BLOCK: u64 = 0;
/// A native word with distinct bytes proves SAME is word-, not byte-, based.
const MIXED_SAME_WORD: usize = 0x0807_0605_0403_0201;
/// Primary-page fixture needs one whole zram page in 512-byte blocks.
const BLOCKS_PER_PAGE: u32 = PAGE_BYTES as u32 / ZRAM_BLOCK_SIZE;
/// Secondary compressor selection used to classify a primary huge page.
const DEFLATE_PRIORITY_ONE: &str = "algo=deflate priority=1";
/// Recompress every eligible object once with configured priority one.
const RECOMPRESS_PRIORITY_ONE: &str = "priority=1 threshold=0 max_pages=1";
/// Deterministic xorshift seed for an incompressible-page fixture.
const RANDOM_SEED: u32 = 0x9e37_79b9;
const RANDOM_SHIFT_LEFT_A: u32 = 13;
const RANDOM_SHIFT_RIGHT: u32 = 17;
const RANDOM_SHIFT_LEFT_B: u32 = 5;
/// Two successful raw stores retain one current huge page but two lifetime events.
const TWO_HUGE_PAGE_STORES: u64 = 2;
/// One logical slot remains huge after both stores target it.
const ONE_CURRENT_HUGE_PAGE: u64 = 1;
/// Linux's valid explicit algorithm-and-priority recompression form.
const RECOMPRESS_ALGORITHM_AND_PRIORITY: &str = "algo=deflate priority=1 max_pages=0 ignored=linux-next-arg";
/// `incompressible` is a writeback mode, never a Linux recompress mode.
const INVALID_RECOMPRESS_TYPE: &str = "type=incompressible priority=1";
/// Malformed selectors must fail rather than falling back to priority one.
const INVALID_RECOMPRESS_PRIORITY: &str = "priority=invalid";
const INVALID_RECOMPRESS_ALGORITHM: &str = "algo=not-compiled";
const EMPTY_RECOMPRESS_FIELD: &str = "future=";
const BARE_RECOMPRESS_FIELD: &str = "future";

fn page_of_same_word(word: usize) -> alloc::vec::Vec<u8> {
    let mut page = alloc::vec![0; PAGE_BYTES];
    for chunk in page.chunks_exact_mut(core::mem::size_of::<usize>()) { chunk.copy_from_slice(&word.to_ne_bytes()); }
    page
}

fn incompressible_page() -> alloc::vec::Vec<u8> {
    let mut random = RANDOM_SEED;
    let mut page = alloc::vec![0; PAGE_BYTES];
    for byte in &mut page {
        random ^= random << RANDOM_SHIFT_LEFT_A;
        random ^= random >> RANDOM_SHIFT_RIGHT;
        random ^= random << RANDOM_SHIFT_LEFT_B;
        *byte = random as u8;
    }
    page
}

#[test]
fn same_slot_preserves_native_word_and_zero_is_not_empty() {
    let zram = Zram::new();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let page = page_of_same_word(MIXED_SAME_WORD);
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, BLOCKS_PER_PAGE, page.clone())).unwrap();
    let stats = zram.stats();
    assert_eq!(stats.same_pages, 1);
    assert_eq!(stats.orig_data_size, PAGE_BYTES as u64);
    let mut read = BlockRequest::new_read(FIRST_BLOCK, BLOCKS_PER_PAGE, ZRAM_BLOCK_SIZE);
    zram.submit_sync(&mut read).unwrap();
    assert_eq!(read.buffer, page);
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, BLOCKS_PER_PAGE, alloc::vec![0; PAGE_BYTES])).unwrap();
    let zero_stats = zram.stats();
    assert_eq!(zero_stats.same_pages, 1);
    assert_eq!(zero_stats.orig_data_size, PAGE_BYTES as u64);
}

#[test]
fn unsuccessful_secondary_recompression_marks_huge_slot_incompressible() {
    let zram = Zram::new();
    zram.set_recomp_algorithm_text(DEFLATE_PRIORITY_ONE).unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, BLOCKS_PER_PAGE, incompressible_page())).unwrap();
    assert!(zram.state.lock().slots.get(0).unwrap().is_huge());
    zram.recompress_text(RECOMPRESS_PRIORITY_ONE).unwrap();
    let state = zram.state.lock();
    let slot = state.slots.get(0).unwrap();
    assert!(slot.is_incompressible());
    assert_eq!(slot.compression_priority(), Some(crate::state::PRIMARY_COMPRESSION_PRIORITY));
}

#[test]
fn huge_pages_since_counts_each_raw_store_not_only_state_transitions() {
    let zram = Zram::new();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let page = incompressible_page();
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, BLOCKS_PER_PAGE, page.clone())).unwrap();
    zram.submit_sync(&mut BlockRequest::new_write(FIRST_BLOCK, BLOCKS_PER_PAGE, page)).unwrap();
    let stats = zram.stats();
    assert_eq!(stats.huge_pages, ONE_CURRENT_HUGE_PAGE);
    assert_eq!(stats.huge_pages_since, TWO_HUGE_PAGE_STORES);
}

#[test]
fn recompress_matches_linux_argument_and_mode_rules() {
    let zram = Zram::new();
    zram.set_recomp_algorithm_text(DEFLATE_PRIORITY_ONE).unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    assert_eq!(zram.recompress_text(RECOMPRESS_ALGORITHM_AND_PRIORITY), Ok(()));
    assert_eq!(zram.recompress_text(INVALID_RECOMPRESS_TYPE), Err(block::BlockError::Einval));
}

#[test]
fn recompress_rejects_malformed_or_huge_class_selection_without_mutation() {
    let zram = Zram::new();
    zram.set_recomp_algorithm_text(DEFLATE_PRIORITY_ONE).unwrap();
    zram.set_disksize(PAGE_BYTES as u64).unwrap();
    let before = zram.stats();
    // The raw-page boundary is outside Linux's recompressible zsmalloc class.
    let huge_class_threshold = alloc::format!("threshold={}", PAGE_BYTES);
    assert_eq!(zram.recompress_text(INVALID_RECOMPRESS_PRIORITY), Err(block::BlockError::Einval));
    assert_eq!(zram.recompress_text(INVALID_RECOMPRESS_ALGORITHM), Err(block::BlockError::Einval));
    assert_eq!(zram.recompress_text(EMPTY_RECOMPRESS_FIELD), Err(block::BlockError::Einval));
    assert_eq!(zram.recompress_text(BARE_RECOMPRESS_FIELD), Err(block::BlockError::Einval));
    assert_eq!(zram.recompress_text(&huge_class_threshold), Err(block::BlockError::Einval));
    assert_eq!(zram.stats(), before);
}
