// Hosted tests for the notification mechanism itself. The queue, the filter
// and the watch list are all target-independent, so every rule below is
// exercised without a pipe, a task or user memory.
//
// Module manifest:
// - queue:  depth, whole-record reads, and the loss ordering.
// - filter: what a filter accepts and which filters are refused.
// - watch:  the watch list's add/remove bookkeeping and record stamping.

mod filter;
mod queue;
mod watch;

use super::*;

/// Decode a record's `(type, subtype, info)`. # C: O(1)
pub(crate) fn head(record: &[u8]) -> (u32, u32, u32) {
    let w0 = u32::from_ne_bytes([record[0], record[1], record[2], record[3]]);
    let info = u32::from_ne_bytes([record[4], record[5], record[6], record[7]]);
    (w0 & WATCH_TYPE_MASK, w0 >> WATCH_SUBTYPE_SHIFT, info)
}

/// The key serial and auxiliary word of a key-change record. # C: O(1)
pub(crate) fn key_fields(record: &[u8]) -> (i32, u32) {
    (i32::from_ne_bytes([record[8], record[9], record[10], record[11]]),
     u32::from_ne_bytes([record[12], record[13], record[14], record[15]]))
}

/// Split a read's output into records, using each one's declared length.
/// # C: O(len)
pub(crate) fn records(buf: &[u8]) -> alloc::vec::Vec<&[u8]> {
    let mut out = alloc::vec::Vec::new();
    let mut i = 0;
    while i < buf.len() {
        let (_, _, info) = head(&buf[i..]);
        let len = (info & WATCH_INFO_LENGTH) as usize;
        assert!(len >= WATCH_HEADER_SIZE, "a record declares its own length");
        out.push(&buf[i..i + len]);
        i += len;
    }
    out
}
