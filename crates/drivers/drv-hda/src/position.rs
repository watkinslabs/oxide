// DMA-position-buffer slot arithmetic and the link-position fallback.

use crate::uapi::POSBUF_STRIDE;

/// Controller register words for the DMA base, initially disabled. # C: O(1)
pub const fn base_words(pa: u64) -> (u32, u32) {
    (pa as u32, (pa >> 32) as u32)
}

/// Address of one stream's position slot. # C: O(1)
pub const fn slot_va(base: u64, index: u8) -> u64 {
    base + index as u64 * POSBUF_STRIDE
}

/// Prefer the DMA position, falling back when the controller has not written
/// a usable value. Values outside the programmed buffer are never exposed.
/// # C: O(1)
pub const fn select(posbuf: u32, lpib: u32, buffer: u32) -> u32 {
    if buffer == 0 { return 0; }
    let pos = if posbuf == 0 || posbuf == u32::MAX { lpib % buffer } else { posbuf };
    if pos < buffer { pos } else { 0 }
}

#[cfg(test)]
#[path = "tests/position.rs"]
mod tests;
