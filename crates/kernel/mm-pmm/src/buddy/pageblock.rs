//! Compact pageblock migratetype map.

use core::sync::atomic::{AtomicU64, Ordering};
use crate::zone::{MigrateType, PAGEBLOCK_ORDER};

const TYPES_PER_WORD: u64 = 32;
const TYPE_BITS: u64 = 2;
const TYPE_MASK: u64 = 0b11;

/// One shared two-bit map over every pageblock in the PMM span.
#[derive(Copy, Clone)]
pub(super) struct PageblockTypes { words: &'static [AtomicU64] }

impl PageblockTypes {
    pub(super) fn new(words: &'static [AtomicU64]) -> Self { Self { words } }

    pub(super) fn words_for(pfn_max: u64) -> usize {
        let blocks = pfn_max.saturating_add((1u64 << PAGEBLOCK_ORDER) - 1) >> PAGEBLOCK_ORDER;
        blocks.saturating_add(TYPES_PER_WORD - 1).saturating_div(TYPES_PER_WORD) as usize
    }

    pub(super) fn get(&self, pfn: u64) -> MigrateType {
        let block = pfn >> PAGEBLOCK_ORDER;
        let word = (block / TYPES_PER_WORD) as usize;
        let shift = (block % TYPES_PER_WORD) * TYPE_BITS;
        let value = (self.words[word].load(Ordering::Acquire) >> shift) & TYPE_MASK;
        MigrateType::from_index(value as usize)
    }

    pub(super) fn set(&self, block: u64, mt: MigrateType) {
        let word = (block / TYPES_PER_WORD) as usize;
        let shift = (block % TYPES_PER_WORD) * TYPE_BITS;
        let mask = TYPE_MASK << shift;
        let value = (mt as u64) << shift;
        let cell = &self.words[word];
        let mut old = cell.load(Ordering::Acquire);
        loop {
            let new = (old & !mask) | value;
            match cell.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return,
                Err(next) => old = next,
            }
        }
    }

    /// Set every pageblock intersecting the half-open range. Callers keep
    /// movable-zone boundaries and claimed blocks pageblock-aligned.
    pub(super) fn set_range(&self, start_pfn: u64, end_pfn: u64, mt: MigrateType) {
        if end_pfn <= start_pfn { return; }
        let first = start_pfn >> PAGEBLOCK_ORDER;
        let last = end_pfn.saturating_sub(1) >> PAGEBLOCK_ORDER;
        for block in first..=last { self.set(block, mt); }
    }
}
