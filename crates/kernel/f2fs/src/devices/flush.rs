//! The segment range one member's blocks occupy.
//!
//! Emptying a member means cleaning every segment that lands on it, so the
//! whole of the operation is a segment range and a cursor into it. The range
//! is arithmetic on the member's span; getting it wrong cleans another
//! member's segments, which is work done in the wrong place rather than
//! damage, but it also leaves the member that was to be emptied full.

use crate::sb::SuperBlock;

use super::table::DevTable;

/// First and last-plus-one main-area segment of member `dev_num`.
///
/// Member zero starts at segment zero rather than at the segment its first
/// block falls in: its span begins in the metadata, which is in no segment of
/// the main area at all.
/// # C: O(devices)
pub fn segno_range(sb: &SuperBlock, table: &DevTable, dev_num: usize) -> Option<(u32, u32)> {
    let d = table.get(dev_num)?;
    let start = if dev_num == 0 { 0 } else { sb.segno_of(d.start_blk)? };
    let end = sb.segno_of(d.end_blk)?;
    if end < start { return None; }
    Some((start, end))
}

/// The segments one request should clean: at most `segments` of them, from
/// `cursor` when it already points into the member, and from the member's
/// first segment when it does not.
/// # C: O(devices)
pub fn window(sb: &SuperBlock, table: &DevTable, dev_num: usize, segments: u32, cursor: u32)
    -> Option<(u32, u32)> {
    let (first, last) = segno_range(sb, table, dev_num)?;
    let start = if cursor < first || cursor >= last { first } else { cursor };
    Some((start, start.saturating_add(segments).min(last)))
}
