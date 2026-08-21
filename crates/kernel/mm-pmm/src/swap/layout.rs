//! Swap-header layout and persistent swapfile geometry validation.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use block::{BlockDevice, BlockRequest};

use super::{Result, SwapError};

pub(super) const SWAP_HEADER_PAGE: u64 = 0;
pub(super) const FIRST_DATA_PAGE: u64 = SWAP_HEADER_PAGE + 1;
pub(super) const SWAP_HEADER_U32_BYTES: usize = core::mem::size_of::<u32>();
pub(super) const SWAPSPACE2_VERSION: u32 = 1;
pub(super) const SWAP_HEADER_VERSION_OFFSET: usize = 1024;
pub(super) const SWAP_HEADER_LAST_PAGE_OFFSET: usize = SWAP_HEADER_VERSION_OFFSET + SWAP_HEADER_U32_BYTES;
pub(super) const SWAP_HEADER_BAD_PAGE_COUNT_OFFSET: usize = SWAP_HEADER_LAST_PAGE_OFFSET + SWAP_HEADER_U32_BYTES;
pub(super) const SWAP_HEADER_BAD_PAGES_OFFSET: usize = SWAP_HEADER_BAD_PAGE_COUNT_OFFSET + SWAP_HEADER_U32_BYTES;
pub(super) const SWAP_MAGIC: &[u8; 10] = b"SWAPSPACE2";

pub(super) struct SwapLayout { pub slots: usize, pub bad_pages: Vec<u32> }

/// Persistent raw geometry of one active swapfile. Page `n` in the logical
/// swap area lives at `pages[n]` on `device_name`.
#[derive(Clone)]
pub struct SwapFileGeometry {
    pub device_name: String,
    pub pages: Vec<u64>,
    pub device: Arc<dyn BlockDevice>,
}

pub(super) fn read_swap_layout(device: &Arc<dyn BlockDevice>) -> Result<SwapLayout> {
    let block_size = device.block_size() as u64;
    let page_size = hal::PAGE_SIZE_BYTES;
    if block_size == 0 || page_size % block_size != 0 { return Err(SwapError::Inval); }
    let blocks_per_page = u32::try_from(page_size / block_size).map_err(|_| SwapError::Inval)?;
    let pages = device.capacity_blocks() / blocks_per_page as u64;
    if pages <= FIRST_DATA_PAGE { return Err(SwapError::Inval); }
    let mut request = BlockRequest::new_read(SWAP_HEADER_PAGE, blocks_per_page, device.block_size());
    device.submit_sync(&mut request).map_err(SwapError::from)?;
    let page = request.buffer;
    let magic_at = page.len().checked_sub(SWAP_MAGIC.len()).ok_or(SwapError::Inval)?;
    if page.get(magic_at..) != Some(SWAP_MAGIC) { return Err(SwapError::Inval); }
    let word = |off: usize| -> Result<u32> {
        let bytes: [u8; SWAP_HEADER_U32_BYTES] = page.get(off..off + SWAP_HEADER_U32_BYTES)
            .ok_or(SwapError::Inval)?.try_into().map_err(|_| SwapError::Inval)?;
        Ok(u32::from_le_bytes(bytes))
    };
    if word(SWAP_HEADER_VERSION_OFFSET)? != SWAPSPACE2_VERSION { return Err(SwapError::Inval); }
    let last_page = word(SWAP_HEADER_LAST_PAGE_OFFSET)? as u64;
    if last_page < FIRST_DATA_PAGE || last_page >= pages { return Err(SwapError::Inval); }
    let bad_count = word(SWAP_HEADER_BAD_PAGE_COUNT_OFFSET)? as usize;
    let bad_end = SWAP_HEADER_BAD_PAGES_OFFSET.checked_add(
        bad_count.checked_mul(SWAP_HEADER_U32_BYTES).ok_or(SwapError::Inval)?)
        .ok_or(SwapError::Inval)?;
    if bad_end > magic_at { return Err(SwapError::Inval); }
    let mut bad_pages = Vec::new();
    bad_pages.try_reserve_exact(bad_count).map_err(|_| SwapError::NoMem)?;
    for index in 0..bad_count {
        let bad = word(SWAP_HEADER_BAD_PAGES_OFFSET + index * SWAP_HEADER_U32_BYTES)?;
        if (bad as u64) < FIRST_DATA_PAGE || (bad as u64) > last_page
            || bad_pages.contains(&bad) { return Err(SwapError::Inval); }
        bad_pages.push(bad);
    }
    let slots = usize::try_from(last_page.checked_add(1).ok_or(SwapError::Inval)?)
        .map_err(|_| SwapError::Inval)?;
    Ok(SwapLayout { slots, bad_pages })
}

pub(super) fn validate_file_geometry(geometry: &SwapFileGeometry, slots: usize) -> Result<()> {
    if geometry.device_name.is_empty() || geometry.pages.len() != slots { return Err(SwapError::Inval); }
    let block_size = geometry.device.block_size() as u64;
    if block_size == 0 || hal::PAGE_SIZE_BYTES % block_size != 0 { return Err(SwapError::Inval); }
    let page_count = geometry.device.capacity_blocks() / (hal::PAGE_SIZE_BYTES / block_size);
    let mut seen = BTreeSet::new();
    for page in &geometry.pages {
        if *page >= page_count || !seen.insert(*page) { return Err(SwapError::Inval); }
    }
    Ok(())
}
