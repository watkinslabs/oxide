//! Dynamically registered unwind function tables. Generated code has no image
//! whose exception directory the unwinder can read, so its producer registers
//! the code range and either the entry table itself or a callback that
//! supplies one entry on demand. The registration is process-wide, and the
//! entry lookup consults it after the loaded images.

use alloc::vec::Vec;

/// Bytes one x86-64 unwind entry occupies: two code addresses and the unwind
/// data address, each image-relative.
pub const ENTRY_BYTES: u64 = 12;
/// Offset of the entry's first code address.
pub const BEGIN_ADDRESS_OFFSET: u64 = 0;
/// Offset of the entry's one-past-last code address.
pub const END_ADDRESS_OFFSET: u64 = 4;
/// Offset of the entry's unwind data address.
pub const UNWIND_DATA_OFFSET: u64 = 8;
/// Low bit of an unwind data address, set when the entry defers to another.
pub const CHAINED_ENTRY: u32 = 1;
/// Both low bits of a callback registration's table word must be set; the
/// pair is what distinguishes it from a table address.
pub const CALLBACK_TABLE_TAG: u64 = 3;
/// Entries a callback registration reports, which is the one it returns.
pub const CALLBACK_ENTRY_COUNT: u32 = 1;
/// Chained entries a lookup follows before treating the chain as a cycle.
pub const CHAIN_DEPTH_LIMIT: u32 = 32;

/// One registered range. `table` is the entry array for a static registration
/// and the tagged identity word for a callback one; `callback` is zero unless
/// the registration supplies entries on demand.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub base: u64,
    pub end: u64,
    pub table: u64,
    pub count: u32,
    pub max_count: u32,
    pub callback: u64,
    pub context: u64,
}

/// What a lookup that lands in a registered range must do next.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Found {
    /// Search this many entries starting at the table address.
    Table { base: u64, table: u64, count: u32 },
    /// Ask this callback, which answers with one entry for the address.
    Callback { base: u64, callback: u64, context: u64 },
}

/// Locate the registration covering `pc`, in registration order.
/// # C: O(N_registrations)
pub fn lookup(entries: &[Entry], pc: u64) -> Option<Found> {
    for entry in entries {
        if pc < entry.base || pc >= entry.end { continue; }
        return Some(if entry.callback != 0 {
            Found::Callback { base: entry.base, callback: entry.callback, context: entry.context }
        } else {
            Found::Table { base: entry.base, table: entry.table, count: entry.count }
        });
    }
    None
}

/// Admit one callback registration. Both low bits of the table word carry the
/// tag that tells a registration apart from a table address; a word without
/// them is refused before any state changes.
/// # C: O(1)
pub fn callback_entry(table: u64, base: u64, length: u32, callback: u64, context: u64) -> Option<Entry> {
    if table & CALLBACK_TABLE_TAG != CALLBACK_TABLE_TAG { return None; }
    Some(Entry { base, end: base.wrapping_add(length as u64), table, count: 0, max_count: 0, callback, context })
}

/// The end of the code a static registration covers: the last entry's own end
/// address, image-relative, added to the base. An empty table covers nothing.
/// # C: O(1)
pub fn static_range_end(base: u64, count: u32, last_end_address: Option<u32>) -> u64 {
    if count == 0 { return base; }
    base.wrapping_add(last_end_address.unwrap_or(0) as u64)
}

/// Build one static registration over an already-measured range.
/// # C: O(1)
pub fn static_entry(table: u64, count: u32, base: u64, end: u64) -> Entry {
    Entry { base, end, table, count, max_count: 0, callback: 0, context: 0 }
}

/// Remove the registration whose entry table is `table`, reporting whether one
/// was found. Only the first match leaves, as the list holds one per table.
/// # C: O(N_registrations)
pub fn remove_by_table(entries: &mut Vec<Entry>, table: u64) -> bool {
    let Some(at) = entries.iter().position(|entry| entry.table == table) else { return false; };
    entries.remove(at);
    true
}

/// Index of the entry covering `offset` within a sorted entry array, given a
/// reader for the two code addresses of one entry. The array is ordered by
/// start address, so the search halves it.
/// # C: O(log N_entries)
pub fn find_entry<F: Fn(u32) -> Option<(u32, u32)>>(count: u32, offset: u32, bounds: F) -> Option<u32> {
    let mut low = 0i64;
    let mut high = count as i64 - 1;
    while low <= high {
        let middle = (low + high) / 2;
        let (begin, end) = bounds(middle as u32)?;
        if offset < begin { high = middle - 1; }
        else if offset >= end { low = middle + 1; }
        else { return Some(middle as u32); }
    }
    None
}

#[cfg(test)]
#[path = "nt_function_table/tests.rs"]
mod tests;
