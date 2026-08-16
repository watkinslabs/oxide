// CORB/RIRB ring arithmetic, kept away from the MMIO so the pointer rules
// can be exercised without a controller: the CORB write pointer advances
// before the entry is claimed, and the RIRB read pointer chases the
// hardware's write pointer one entry at a time.

use crate::uapi::{CORB_ENTRIES, RIRB_ENTRIES};

/// Read pointer value the controller reports when it is powered down.
pub const POINTER_INVALID: u16 = 0xffff;

/// Next CORB write position, or `None` when the ring is full or the
/// controller is not answering.
/// # C: O(1)
pub fn corb_next_write(write: u16, read: u16) -> Option<u16> {
    if write == POINTER_INVALID || read == POINTER_INVALID { return None; }
    let next = (write + 1) % CORB_ENTRIES as u16;
    if next == read % CORB_ENTRIES as u16 { None } else { Some(next) }
}

/// Byte offset of CORB entry `index`. # C: O(1)
pub fn corb_offset(index: u16) -> usize { index as usize * crate::uapi::CORB_ENTRY_BYTES }

/// Entries the RIRB has produced since `read`, in arrival order. # C: O(1)
pub fn rirb_pending(read: u16, hardware_write: u16) -> u16 {
    if hardware_write == POINTER_INVALID { return 0; }
    (hardware_write + RIRB_ENTRIES as u16 - read) % RIRB_ENTRIES as u16
}

/// Advance the RIRB read pointer one entry and give the dword index of the
/// entry it now points at. # C: O(1)
pub fn rirb_step(read: u16) -> (u16, usize) {
    let next = (read + 1) % RIRB_ENTRIES as u16;
    (next, next as usize * 2)
}

#[cfg(test)]
#[path = "tests/ring.rs"]
mod tests;
