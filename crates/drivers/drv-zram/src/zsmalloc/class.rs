//! Linux-shaped zsmalloc size-class derivation.

use block::{BlockError, KResult};

use super::limits::{ZS_CLASS_DELTA_BYTES, ZS_FULLNESS_THRESHOLD_FRAC, ZS_MAX_PAGES_PER_ZSPAGE, ZS_MIN_OBJECT_BYTES};

/// Linux zsmalloc's per-size-class zspage fullness grouping.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) enum Fullness {
    Empty,
    AlmostEmpty,
    Middle,
    AlmostFull,
    Full,
}

impl Fullness {
    /// Classifies a zspage from its exact live-object count.
    /// # C: O(1)
    pub(super) fn from_live(live: usize, capacity: usize) -> Self {
        if live == 0 { return Self::Empty; }
        if live == capacity { return Self::Full; }
        let boundary = capacity / ZS_FULLNESS_THRESHOLD_FRAC;
        if live <= boundary { return Self::AlmostEmpty; }
        if live > capacity.saturating_sub(boundary) { return Self::AlmostFull; }
        Self::Middle
    }

    /// Stable index for per-class fullness group accounting.
    /// # C: O(1)
    pub(super) const fn index(self) -> usize {
        match self {
            Self::Empty => 0,
            Self::AlmostEmpty => 1,
            Self::Middle => 2,
            Self::AlmostFull => 3,
            Self::Full => 4,
        }
    }
}

/// One zsmalloc size class and the shape of each zspage it owns.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) struct SizeClass {
    pub(super) object_bytes: usize,
    pub(super) pages_per_zspage: usize,
    pub(super) objects_per_zspage: usize,
}

impl SizeClass {
    /// Maps an allocation request to Linux's first fitting fixed-size class.
    /// # C: O(1)
    pub(super) fn for_request(request_bytes: usize) -> KResult<Self> {
        let page_bytes = hal::PAGE_SIZE_BYTES as usize;
        if request_bytes == 0 || request_bytes > page_bytes { return Err(BlockError::Einval); }
        let object_bytes = class_bytes(request_bytes, page_bytes)?;
        let pages_per_zspage = chain_pages(object_bytes, page_bytes);
        let zspage_bytes = pages_per_zspage.checked_mul(page_bytes).ok_or(BlockError::Enomem)?;
        let objects_per_zspage = zspage_bytes / object_bytes;
        if objects_per_zspage == 0 { return Err(BlockError::Eio); }
        Ok(Self { object_bytes, pages_per_zspage, objects_per_zspage })
    }
}

fn class_bytes(request_bytes: usize, page_bytes: usize) -> KResult<usize> {
    if request_bytes <= ZS_MIN_OBJECT_BYTES { return Ok(ZS_MIN_OBJECT_BYTES); }
    let beyond_minimum = request_bytes.checked_sub(ZS_MIN_OBJECT_BYTES).ok_or(BlockError::Einval)?;
    let steps = beyond_minimum.checked_add(ZS_CLASS_DELTA_BYTES - 1).ok_or(BlockError::Enomem)? / ZS_CLASS_DELTA_BYTES;
    ZS_MIN_OBJECT_BYTES.checked_add(steps.checked_mul(ZS_CLASS_DELTA_BYTES).ok_or(BlockError::Enomem)?).filter(|size| *size <= page_bytes).ok_or(BlockError::Einval)
}

/// Exact Linux `calculate_zspage_chain_size`: choose the chain with least tail waste.
fn chain_pages(object_bytes: usize, page_bytes: usize) -> usize {
    if object_bytes.is_power_of_two() { return 1; }
    let mut chain_pages = 1;
    let mut least_waste = page_bytes % object_bytes;
    let mut candidate = 2;
    while candidate <= ZS_MAX_PAGES_PER_ZSPAGE {
        let waste = (candidate * page_bytes) % object_bytes;
        if waste < least_waste {
            least_waste = waste;
            chain_pages = candidate;
        }
        candidate += 1;
    }
    chain_pages
}
