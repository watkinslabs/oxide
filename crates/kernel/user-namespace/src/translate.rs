// Linux `make_kuid`/`from_kuid_munged` id translation (`kernel/user_namespace.c`
// `map_id_range_down`/`map_id_up`). An id `x` inside the namespace maps to
// `host_id + (x - ns_id)` for the extent with `ns_id <= x < ns_id + count`;
// an id with no covering extent maps to the overflow id.

use crate::extent::IdMapExtent;
use crate::uapi::{OVERFLOW_GID, OVERFLOW_UID};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OverflowId { Uid, Gid }

impl OverflowId {
    /// # C: O(1)
    const fn value(self) -> u32 {
        match self { Self::Uid => OVERFLOW_UID, Self::Gid => OVERFLOW_GID }
    }
}

/// Translate a namespace-relative id to its host id (Linux `make_kuid`
/// direction: userspace argument -> internal id). Unmapped -> overflow id.
/// # C: O(map.len())
pub fn to_host(map: &[IdMapExtent], ns_id: u32, overflow: OverflowId) -> u32 {
    for extent in map {
        let Some(offset) = ns_id.checked_sub(extent.ns_id) else { continue; };
        if offset < extent.count {
            // extent validation guarantees host_id + offset fits in u32.
            return extent.host_id + offset;
        }
    }
    overflow.value()
}

/// Translate a host id to its namespace-relative id (Linux
/// `from_kuid_munged` direction: internal id -> userspace-visible id).
/// Unmapped -> overflow id. # C: O(map.len())
pub fn to_ns(map: &[IdMapExtent], host_id: u32, overflow: OverflowId) -> u32 {
    for extent in map {
        let Some(offset) = host_id.checked_sub(extent.host_id) else { continue; };
        if offset < extent.count {
            return extent.ns_id + offset;
        }
    }
    overflow.value()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> [IdMapExtent; 2] {
        [
            IdMapExtent { ns_id: 0, host_id: 100_000, count: 10 },
            IdMapExtent { ns_id: 1000, host_id: 0, count: 1 },
        ]
    }

    #[test]
    fn maps_id_inside_an_extent() {
        assert_eq!(to_host(&map(), 5, OverflowId::Uid), 100_005);
        assert_eq!(to_ns(&map(), 100_005, OverflowId::Uid), 5);
    }

    #[test]
    fn maps_boundary_ids_at_both_extent_edges() {
        assert_eq!(to_host(&map(), 0, OverflowId::Uid), 100_000);
        assert_eq!(to_host(&map(), 9, OverflowId::Uid), 100_009);
        assert_eq!(to_host(&map(), 1000, OverflowId::Uid), 0);
    }

    #[test]
    fn unmapped_id_translates_to_overflow() {
        assert_eq!(to_host(&map(), 10, OverflowId::Uid), OVERFLOW_UID);
        assert_eq!(to_host(&map(), 999, OverflowId::Gid), OVERFLOW_GID);
        assert_eq!(to_ns(&map(), 200_000, OverflowId::Uid), OVERFLOW_UID);
    }

    #[test]
    fn empty_map_translates_every_id_to_overflow() {
        assert_eq!(to_host(&[], 0, OverflowId::Uid), OVERFLOW_UID);
        assert_eq!(to_ns(&[], 0, OverflowId::Gid), OVERFLOW_GID);
    }
}
