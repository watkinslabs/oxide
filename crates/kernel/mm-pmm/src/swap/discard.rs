//! Linux swapon discard policy and physical free-range submission.

use super::{Area, FIRST_DATA_PAGE, Result, SwapError};
use block::{BlockDevice, BlockRequest};

/// Largest request representable by the canonical block request ABI.
const MAX_BLOCK_REQUEST_BLOCKS: u64 = u32::MAX as u64;

/// Requested `SWAP_FLAG_DISCARD*` policy after Linux's flag precedence rules.
/// `SWAP_FLAG_DISCARD` without a selector enables both activation-time and
/// free-page discard; `ONCE` wins when both selectors are supplied.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SwapDiscard {
    None,
    Once,
    Pages,
    Both,
}

impl SwapDiscard {
    /// Translate the three Linux UAPI booleans without importing syscall ABI
    /// constants into the canonical PMM owner. # C: O(1)
    pub const fn from_swapon(enabled: bool, once: bool, pages: bool) -> Self {
        if !enabled { Self::None }
        else if once { Self::Once }
        else if pages { Self::Pages }
        else { Self::Both }
    }

    /// Discard is effective only when the actual backing queue advertised it.
    /// Linux accepts the flags for incapable queues but installs no policy.
    /// # C: O(1)
    pub const fn for_device(self, supported: bool) -> Self {
        if supported { self } else { Self::None }
    }

    /// Whether a swapon-time free-area discard is required. # C: O(1)
    pub const fn once(self) -> bool { matches!(self, Self::Once | Self::Both) }
    /// Whether final swap-page release must issue a physical discard. # C: O(1)
    pub const fn pages(self) -> bool { matches!(self, Self::Pages | Self::Both) }
}

/// Discard all currently-free runs in one newly activated area. The swap
/// header and mkswap bad pages stay untouched. Linux logs a failure here but
/// keeps the area active, so the caller deliberately ignores this result.
/// # C: O(area slots + discard I/O)
pub(super) fn discard_free_area(area: &Area) -> Result<()> {
    let mut first = FIRST_DATA_PAGE as usize;
    while first < area.slot_count {
        while first < area.slot_count && area.slot(first) != Some(super::Slot::Free) { first += 1; }
        if first == area.slot_count { break; }
        let mut last = first + 1;
        while last < area.slot_count && area.slot(last) == Some(super::Slot::Free) { last += 1; }
        discard_slots(area, first, last)?;
        first = last;
    }
    Ok(())
}

/// Submit one backend discard after a final swap PTE release. # C: O(discard I/O)
pub(super) fn discard_range(device: &dyn BlockDevice, start: u64, blocks: u32) -> Result<()> {
    let mut request = BlockRequest::new_discard(start, blocks);
    device.submit_sync(&mut request).map_err(SwapError::from)
}

fn discard_slots(area: &Area, first: usize, end: usize) -> Result<()> {
    let slots = end.checked_sub(first).ok_or(SwapError::Inval)?;
    if slots == 0 { return Ok(()); }
    let mut start = area.page_block(first as u64)?;
    let mut left = (slots as u64).checked_mul(area.blocks_per_page as u64).ok_or(SwapError::Inval)?;
    while left != 0 {
        let blocks = left.min(MAX_BLOCK_REQUEST_BLOCKS) as u32;
        discard_range(area.device.as_ref(), start, blocks)?;
        start = start.checked_add(blocks as u64).ok_or(SwapError::Inval)?;
        left -= blocks as u64;
    }
    Ok(())
}
