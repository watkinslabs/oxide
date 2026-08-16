// Buffer descriptor list construction and the ring arithmetic over the DMA
// buffer. The controller walks the BDL forever; each entry names a physical
// span and whether finishing it raises an interrupt.

use alloc::vec::Vec;

use crate::uapi::*;

/// One 16-byte BDL entry as four little-endian words.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Bdle {
    pub addr: u64,
    pub len: u32,
    pub ioc: bool,
}

/// Geometry of a prepared stream.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Geometry {
    pub period_bytes: u32,
    pub periods: u32,
}

impl Geometry {
    pub fn buffer_bytes(&self) -> u32 { self.period_bytes * self.periods }
}

/// Round a requested period down to the 128-byte block the controller needs,
/// never below one block. # C: O(1)
pub fn align_period(bytes: u32) -> u32 {
    let aligned = bytes - (bytes % PERIOD_ALIGN_BYTES);
    if aligned == 0 { PERIOD_ALIGN_BYTES } else { aligned }
}

/// Split a contiguous DMA buffer into one BDL entry per period, each raising
/// an interrupt on completion. A period that would straddle a 4 KiB boundary
/// is split into two entries, with the interrupt on the second — a BDL entry
/// may not cross that boundary on every controller.
/// # C: O(periods)
pub fn build(buffer_pa: u64, geometry: &Geometry) -> Option<Vec<Bdle>> {
    if geometry.period_bytes == 0 || geometry.periods == 0 { return None; }
    let mut entries: Vec<Bdle> = Vec::new();
    let mut offset: u64 = 0;
    for _ in 0..geometry.periods {
        let mut remaining = geometry.period_bytes;
        while remaining > 0 {
            let addr = buffer_pa + offset;
            let to_boundary = 0x1000 - (addr & 0xfff);
            let chunk = u32::min(remaining, to_boundary as u32);
            remaining -= chunk;
            offset += u64::from(chunk);
            if entries.len() == BDL_MAX_ENTRIES { return None; }
            entries.push(Bdle { addr, len: chunk, ioc: remaining == 0 });
        }
    }
    Some(entries)
}

/// Serialise a BDL entry into the four words the controller reads.
/// # C: O(1)
pub fn encode(entry: &Bdle) -> [u32; 4] {
    [entry.addr as u32, (entry.addr >> 32) as u32, entry.len,
     if entry.ioc { BDL_IOC } else { 0 }]
}

/// Free bytes between the hardware's read position and the driver's write
/// position in a `size`-byte ring, leaving the ring never completely full so
/// full and empty stay distinguishable.
/// # C: O(1)
pub fn writable(size: u32, write: u32, hw_read: u32) -> u32 {
    if size == 0 { return 0; }
    let used = write.wrapping_sub(hw_read) % size;
    size - used - 1
}

/// Advance a ring offset. # C: O(1)
pub fn advance(size: u32, offset: u32, by: u32) -> u32 {
    if size == 0 { 0 } else { (offset + by) % size }
}

/// Split a copy of `len` bytes starting at `offset` into the pieces before
/// and after the wrap. # C: O(1)
pub fn split_at_wrap(size: u32, offset: u32, len: u32) -> (u32, u32) {
    let head = u32::min(len, size.saturating_sub(offset));
    (head, len - head)
}

/// Frames the hardware has consumed in total, from a byte position that
/// wraps within the buffer plus the number of completed laps.
/// # C: O(1)
pub fn total_frames(laps: u64, buffer_bytes: u32, position: u32, frame_bytes: u32) -> u64 {
    if frame_bytes == 0 { return 0; }
    (laps * u64::from(buffer_bytes) + u64::from(position)) / u64::from(frame_bytes)
}

#[cfg(test)]
#[path = "tests/bdl.rs"]
mod tests;
