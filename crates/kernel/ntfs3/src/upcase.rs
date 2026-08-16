//! The `$UpCase` file: the volume's own answer to which two names are the same
//! name, and the ORDER its directories are sorted in.
//!
//! This matters more here than on exFAT, because the table does not only
//! decide equality — it decides the B-tree's ordering. A descent using a
//! different fold walks to the wrong child and reports a file that is there as
//! absent, without any structure looking damaged.
//!
//! The stored form is flat: 65536 UTF-16 units, each the upper case of its own
//! index. There is no compression and no checksum.

use alloc::vec::Vec;

use crate::uapi::NTFS_NAME_LEN;

/// Units in a full table.
pub const UPCASE_UNITS: usize = 0x10000;

/// A volume's case-folding and ordering answer.
pub struct UpCase {
    table: Vec<u16>,
}

impl UpCase {
    /// The upper case of one unit.
    ///
    /// ASCII is folded by arithmetic before the table is consulted, exactly as
    /// the reference does: a volume whose table disagrees about ASCII would
    /// otherwise sort its own directories in an order Windows does not.
    /// # C: O(1)
    pub fn fold(&self, unit: u16) -> u16 {
        if unit < u16::from(b'a') { return unit; }
        if unit <= u16::from(b'z') { return unit - (u16::from(b'a') - u16::from(b'A')); }
        self.table[unit as usize]
    }

    /// The table's units. # C: O(1)
    pub fn raw(&self) -> &[u16] { &self.table }
}

/// Load a table from `$UpCase`'s data.
///
/// A short or absent table folds by the built-in rules rather than refusing
/// the mount: the alternative is a medium that will not mount because of a
/// file nothing else reads.
/// # C: O(UPCASE_UNITS)
pub fn load(data: &[u8]) -> UpCase {
    let mut table = builtin_table();
    for (index, pair) in data.chunks_exact(2).enumerate().take(UPCASE_UNITS) {
        table[index] = u16::from_le_bytes([pair[0], pair[1]]);
    }
    UpCase { table }
}

/// The table used when the volume's own cannot be read. # C: O(UPCASE_UNITS)
pub fn builtin() -> UpCase { UpCase { table: builtin_table() } }

/// Every unit's upper case by the built-in rules, which is identity outside
/// the blocks that fold. # C: O(UPCASE_UNITS)
fn builtin_table() -> Vec<u16> {
    let mut out: Vec<u16> = (0..UPCASE_UNITS as u32).map(|i| i as u16).collect();
    for (lower, upper) in crate::upcase_rules::PAIRS.iter().copied() {
        out[lower as usize] = upper;
    }
    out
}

/// Lay a table out as `$UpCase`'s data, for a test that builds a volume.
/// # C: O(UPCASE_UNITS)
pub fn pack(table: &UpCase) -> Vec<u8> {
    let mut out = Vec::with_capacity(UPCASE_UNITS * 2);
    for unit in table.raw() { out.extend_from_slice(&unit.to_le_bytes()); }
    out
}

/// Compare two names as this volume orders them.
///
/// `both_cases` first compares exactly and only falls back to the fold when
/// the two differ, which is what makes two names differing only in case sort
/// stably rather than arbitrarily. That is the reference's own rule, and a
/// B-tree built under it is not searchable under any other.
/// # C: O(shorter name)
pub fn compare(a: &[u16], b: &[u16], table: &UpCase, both_cases: bool) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    let len = core::cmp::min(a.len(), b.len());
    let mut exact = Ordering::Equal;
    if both_cases {
        for i in 0..len {
            match a[i].cmp(&b[i]) {
                Ordering::Equal => {}
                other => { exact = other; break; }
            }
        }
        if exact == Ordering::Equal { return a.len().cmp(&b.len()); }
    }
    for i in 0..len {
        match table.fold(a[i]).cmp(&table.fold(b[i])) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    match a.len().cmp(&b.len()) {
        Ordering::Equal => exact,
        other => other,
    }
}

/// Whether two names are the same name on this volume. # C: O(shorter name)
pub fn eq(a: &[u16], b: &[u16], table: &UpCase) -> bool {
    a.len() == b.len() && compare(a, b, table, false) == core::cmp::Ordering::Equal
}

/// Whether a name is short enough for this filesystem. # C: O(1)
pub fn name_fits(units: &[u16]) -> bool { !units.is_empty() && units.len() <= NTFS_NAME_LEN }

#[cfg(test)]
#[path = "tests/upcase.rs"]
mod tests;
