// One `uid_map`/`gid_map` line + the batch validation Linux applies to a
// whole write(2) before any of it is committed (`kernel/user_namespace.c`
// `map_write`/`mappings_overlap`).

use alloc::vec::Vec;

use crate::uapi::UID_GID_MAP_MAX_EXTENTS;

/// One parsed `<ns_id> <host_id> <count>` map line.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IdMapExtent {
    pub ns_id: u32,
    pub host_id: u32,
    pub count: u32,
}

impl IdMapExtent {
    /// Inclusive last ns id covered, or `None` on zero count / overflow. # C: O(1)
    fn ns_last(self) -> Option<u32> { self.count.checked_sub(1).and_then(|c| self.ns_id.checked_add(c)) }
    /// Inclusive last host id covered, or `None` on zero count / overflow. # C: O(1)
    fn host_last(self) -> Option<u32> { self.count.checked_sub(1).and_then(|c| self.host_id.checked_add(c)) }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExtentError { Empty, TooMany, ZeroCount, RangeOverflow, Overlap }

/// True when `[a_first,a_last]` and `[b_first,b_last]` intersect. # C: O(1)
fn ranges_intersect(a_first: u32, a_last: u32, b_first: u32, b_last: u32) -> bool {
    a_first <= b_last && b_first <= a_last
}

/// Validate one candidate extent batch exactly as Linux `map_write` does
/// before any extent is committed: extent count bounds, no zero-count
/// extent, no `ns_id`/`host_id` range overflowing `u32`, and no pairwise
/// overlap in EITHER the ns-id space or the host-id space (Linux
/// `mappings_overlap` checks both independently — a host id aliased by
/// two ns ids is as invalid as an ns id aliased by two host ids).
/// # C: O(n^2) on `extents.len()` (n <= `UID_GID_MAP_MAX_EXTENTS`)
pub fn validate_extents(extents: &[IdMapExtent]) -> Result<(), ExtentError> {
    if extents.is_empty() { return Err(ExtentError::Empty); }
    if extents.len() > UID_GID_MAP_MAX_EXTENTS { return Err(ExtentError::TooMany); }
    let mut committed: Vec<(u32, u32, u32, u32)> = Vec::with_capacity(extents.len());
    for extent in extents {
        if extent.count == 0 { return Err(ExtentError::ZeroCount); }
        let ns_last = extent.ns_last().ok_or(ExtentError::RangeOverflow)?;
        let host_last = extent.host_last().ok_or(ExtentError::RangeOverflow)?;
        for &(prev_ns_first, prev_ns_last, prev_host_first, prev_host_last) in &committed {
            if ranges_intersect(extent.ns_id, ns_last, prev_ns_first, prev_ns_last)
                || ranges_intersect(extent.host_id, host_last, prev_host_first, prev_host_last)
            {
                return Err(ExtentError::Overlap);
            }
        }
        committed.push((extent.ns_id, ns_last, extent.host_id, host_last));
    }
    Ok(())
}
