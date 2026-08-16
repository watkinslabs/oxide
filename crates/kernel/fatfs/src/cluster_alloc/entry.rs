//! Writing one table entry.
//!
//! Reading a table is forgiving — a wrong answer shows the wrong bytes.
//! WRITING one is not: a mistake here hands a cluster to two files, or drops
//! one nobody can reach again, and the volume is then wrong for every other
//! system that reads it.
//!
//! A twelve-bit entry shares a byte with its neighbour, so writing one must
//! PRESERVE the other's nibble; a thirty-two-bit entry carries four reserved
//! top bits that belong to whoever wrote them first.

use syscall::errno::Errno;

use crate::chain;
use crate::geometry::FatWidth;

/// End-of-chain value written into the last entry of a chain, per width.
/// Any value at or above the bad mark reads as an end; this is the one the
/// reference writes.
/// # C: O(1)
pub fn end_mark(width: FatWidth) -> u32 {
    match width {
        FatWidth::Fat12 => 0x0000_0FFF,
        FatWidth::Fat16 => 0x0000_FFFF,
        FatWidth::Fat32 => 0x0FFF_FFFF,
    }
}

/// Value written to release an entry.
pub const FREE_MARK: u32 = 0;

/// Write one table entry.
///
/// The twelve-bit case reads the byte pair it shares with its neighbour and
/// merges, because half of that pair belongs to another cluster. Overwriting
/// the pair outright destroys the neighbour's entry — which is a chain
/// truncated or re-pointed somewhere else, discovered later as lost data.
/// # C: O(1)
pub fn write_entry(width: FatWidth, table: &mut [u8], cluster: u32, value: u32) -> Result<(), Errno> {
    let at = usize::try_from(chain::entry_offset(width, cluster)).map_err(|_| Errno::Eio)?;
    let value = value & width.entry_mask();
    match width {
        FatWidth::Fat12 => {
            if at + 1 >= table.len() { return Err(Errno::Eio); }
            let pair = u16::from_le_bytes([table[at], table[at + 1]]);
            let merged = if cluster & 1 == 0 {
                (pair & 0xF000) | (value as u16 & 0x0FFF)
            } else {
                (pair & 0x000F) | ((value as u16 & 0x0FFF) << 4)
            };
            table[at..at + 2].copy_from_slice(&merged.to_le_bytes());
        }
        FatWidth::Fat16 => {
            if at + 1 >= table.len() { return Err(Errno::Eio); }
            table[at..at + 2].copy_from_slice(&(value as u16).to_le_bytes());
        }
        FatWidth::Fat32 => {
            if at + 3 >= table.len() { return Err(Errno::Eio); }
            // The top four bits are reserved and belong to whatever wrote them
            // first; the reference preserves them across a write.
            let existing = u32::from_le_bytes([table[at], table[at + 1], table[at + 2], table[at + 3]]);
            let merged = (existing & 0xF000_0000) | value;
            table[at..at + 4].copy_from_slice(&merged.to_le_bytes());
        }
    }
    Ok(())
}
