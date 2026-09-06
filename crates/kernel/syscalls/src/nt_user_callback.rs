//! The user-mode callback table user32 publishes in its PEB, and the entries
//! win32u work calls back through. A callback runs on the calling thread's
//! frame and answers through NtCallbackReturn.

/// Callback ordinals, in the order the client's callback table declares them.
pub(crate) const NT_USER_INIT_BUILTIN_CLASSES: u32 = 13;
/// Highest ordinal the table can hold.
pub(crate) const NT_USER_CALL_COUNT: u32 = 256;

const TEB_PEB_OFFSET: u64 = 0x60;
const PEB_KERNEL_CALLBACK_TABLE_OFFSET: u64 = 0x58;
const ENTRY_BYTES: u64 = 8;

/// Address of the PEB pointer inside one TEB. # C: O(1)
pub(crate) const fn peb_pointer(teb: u64) -> Option<u64> {
    if teb == 0 { return None; }
    teb.checked_add(TEB_PEB_OFFSET)
}

/// Address of the callback-table pointer inside one PEB. # C: O(1)
pub(crate) const fn table_pointer(peb: u64) -> Option<u64> {
    if peb == 0 { return None; }
    peb.checked_add(PEB_KERNEL_CALLBACK_TABLE_OFFSET)
}

/// Address of one callback entry. A table pointer of zero means user32 has
/// not published its table, and an ordinal past the table's end is a caller
/// defect, not an entry to read. # C: O(1)
pub(crate) const fn entry_pointer(table: u64, index: u32) -> Option<u64> {
    if table == 0 || index >= NT_USER_CALL_COUNT { return None; }
    table.checked_add(index as u64 * ENTRY_BYTES)
}

#[cfg(test)]
#[path = "nt_user_callback/tests.rs"]
mod tests;
