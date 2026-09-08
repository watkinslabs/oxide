//! Per-character advances of one face, and the synchronous text extent every
//! menu measurement is laid out from.
//!
//! A menu item is measured with the extent of its own label under the menu
//! face, not with a character count times an average advance: a proportional
//! label measured on the average overruns its box wherever its glyphs are
//! wider than the mean. The font itself lives in the graphics backend, which
//! the kernel reaches only through a callback that cannot answer inside the
//! nonclient calculation that needs the number. The advances of the face are
//! therefore fetched once, into this table, and every later measurement sums
//! them without leaving the kernel - the same shape the reference gives
//! `menucharsize`, which it also measures once and keeps.
//!
//! Until the face has been measured the table answers the average advance for
//! every character, which is the estimate the layout used before any face was
//! measured at all.

/// The block, the resolution and the wire size all belong to the query that
/// answers them, so the table the backend fills and the table this module
/// reads are one description.
pub const CELL_FIRST: u16 = syscall::nt_native_gdi::MENU_CELL_FIRST as u16;
pub const CELL_COUNT: usize = syscall::nt_native_gdi::MENU_CELL_COUNT as usize;
pub const CELL_SCALE: i32 = syscall::nt_native_gdi::MENU_CELL_SCALE;
pub const CELL_TABLE_BYTES: usize = CELL_COUNT * 2;
/// Bytes the answer carries: the face's cell height ahead of the table.
pub const CELL_ANSWER_BYTES: usize = 4 + CELL_TABLE_BYTES;
/// Divisor the reference quotes one face's character size over: the
/// fifty-two letter sample averaged two characters at a time.
const SAMPLE_DIVISOR: i32 = 26;

/// Advances of one face, in sub-pixel units, plus the cell height it reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MenuCells { advances: [u16; CELL_COUNT], other: u16, height: i32 }

impl MenuCells {
    /// The table a face answers with before it has been measured: one average
    /// advance for every character. # C: O(N_cells)
    pub const fn uniform(advance: i32, height: i32) -> Self {
        let scaled = scale(advance);
        Self { advances: [scaled; CELL_COUNT], other: scaled, height }
    }

    /// The table one measured face reports, as little-endian sub-pixel words
    /// in character order from `CELL_FIRST`. A character outside the measured
    /// block is answered with the mean of the block, which is what an average
    /// advance is. # C: O(N_cells)
    pub fn from_words(words: &[u8], height: i32) -> Option<Self> {
        if words.len() != CELL_TABLE_BYTES { return None; }
        let mut advances = [0u16; CELL_COUNT];
        let mut total = 0u32;
        for (index, slot) in advances.iter_mut().enumerate() {
            *slot = u16::from_le_bytes([words[index * 2], words[index * 2 + 1]]);
            total += u32::from(*slot);
        }
        let other = (total / CELL_COUNT as u32) as u16;
        Some(Self { advances, other, height })
    }

    /// The cell height the face reports. # C: O(1)
    pub fn height(&self) -> i32 { self.height }

    /// One character's advance in sub-pixel units. # C: O(1)
    pub fn advance(&self, unit: u16) -> u16 {
        match unit.checked_sub(CELL_FIRST).map(usize::from) {
            Some(index) if index < CELL_COUNT => self.advances[index],
            _ => self.other,
        }
    }

    /// The pixel extent of one run: its advances summed at sub-pixel
    /// resolution and rounded up once, so a run and the sum of its parts
    /// cannot disagree by the rounding of every character. # C: O(N_units)
    pub fn extent(&self, units: &[u16]) -> i32 {
        let mut total: i64 = 0;
        for unit in units { total += i64::from(self.advance(*unit)); }
        let pixels = (total + i64::from(CELL_SCALE) - 1) / i64::from(CELL_SCALE);
        i32::try_from(pixels).unwrap_or(i32::MAX)
    }

    /// The character size every menu measurement pads by: the average advance
    /// of the fifty-two letters, quoted the way the reference quotes one, and
    /// the cell height beside it. # C: O(1)
    pub fn char_size(&self) -> (i32, i32) {
        let mut sample: i64 = 0;
        for unit in (b'a'..=b'z').chain(b'A'..=b'Z') { sample += i64::from(self.advance(u16::from(unit))); }
        let pixels = (sample + i64::from(CELL_SCALE) - 1) / i64::from(CELL_SCALE);
        let width = (i32::try_from(pixels).unwrap_or(i32::MAX) / SAMPLE_DIVISOR + 1) / 2;
        (width.max(1), self.height)
    }
}

/// The table one answer from the font backend carries: the face's cell height
/// ahead of its advances. # C: O(N_cells)
pub fn cells_from_answer(bytes: &[u8]) -> Option<MenuCells> {
    if bytes.len() != CELL_ANSWER_BYTES { return None; }
    let height = i32::from_le_bytes(bytes[..4].try_into().ok()?);
    if height <= 0 { return None; }
    MenuCells::from_words(&bytes[4..], height)
}

/// Sub-pixel form of one whole-pixel advance. # C: O(1)
const fn scale(advance: i32) -> u16 {
    let scaled = if advance < 0 { 0 } else { advance.saturating_mul(CELL_SCALE) };
    if scaled > u16::MAX as i32 { u16::MAX } else { scaled as u16 }
}

#[cfg(test)]
#[path = "tests/menu_cells.rs"]
mod tests;
