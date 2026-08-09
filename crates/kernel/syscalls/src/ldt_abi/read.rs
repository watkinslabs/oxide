// `read_ldt` / `read_default_ldt` sizing rules.
//
// Both sub-functions return a BYTE COUNT, not an entry count, and both
// zero-fill whatever the caller asked for beyond the data that exists. A
// caller that hands in a huge `bytecount` therefore gets a huge zeroed
// buffer and a huge return value — which is why the count is clamped here
// before any copy is attempted.

use super::{LDT_TABLE_BYTES, LDT_ENTRY_SIZE};

/// Bytes `read_default_ldt` reports on the 64-bit ABI. The "default LDT" has
/// no entries at all, so the whole run is zeroes; the number exists only
/// because callers predate the empty-table answer.
pub const DEFAULT_LDT_BYTES: u64 = 128;

/// What a `read` sub-function has to copy out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadPlan {
    /// Bytes taken from the live table, starting at entry 0.
    pub copy: u64,
    /// Bytes of zero fill written directly after them.
    pub zero: u64,
}

impl ReadPlan {
    /// The syscall's return value: everything the caller is told was written.
    /// # C: O(1)
    pub fn retval(&self) -> i64 { (self.copy + self.zero) as i64 }
}

/// Plan `modify_ldt(0, ptr, bytecount)` for a process whose table holds
/// `nr_entries` entries.
///
/// A process that never installed an entry reads back nothing at all — not a
/// zero-filled `bytecount`, but a literal zero return with the buffer
/// untouched. That distinction is the only way a caller can tell "no LDT" from
/// "an LDT of eight zero descriptors".
/// # C: O(1)
pub fn plan_read(nr_entries: u32, bytecount: u64) -> ReadPlan {
    if nr_entries == 0 { return ReadPlan { copy: 0, zero: 0 }; }
    let want = bytecount.min(LDT_TABLE_BYTES);
    let have = nr_entries as u64 * LDT_ENTRY_SIZE as u64;
    let copy = have.min(want);
    ReadPlan { copy, zero: want - copy }
}

/// Plan `modify_ldt(2, ptr, bytecount)`. Nothing is ever copied; the answer
/// is `min(bytecount, 128)` zero bytes.
/// # C: O(1)
pub fn plan_read_default(bytecount: u64) -> ReadPlan {
    ReadPlan { copy: 0, zero: bytecount.min(DEFAULT_LDT_BYTES) }
}
