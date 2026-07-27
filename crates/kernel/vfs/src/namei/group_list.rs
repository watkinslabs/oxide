// Linux `struct group_info` (`include/linux/cred.h`, `kernel/groups.c`): the
// caller's supplementary gid set, carried by every credential snapshot.
//
// Refcounted and ASCENDING-SORTED, exactly like the kernel's: cloning a
// credential shares the array instead of copying it, and membership is the
// `groups_search` binary search. The list is sized by the credential that
// produced it — up to `NGROUPS_MAX` (65536) entries — so a DAC check never
// sees a truncated group set.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// A credential's supplementary group set. `None` is the empty set (Linux
/// `init_groups`) and costs no allocation.
#[derive(Clone, Debug, Default)]
pub struct GroupList(Option<Arc<[u32]>>);

impl GroupList {
    /// The empty set. # C: O(1)
    pub const fn empty() -> Self { Self(None) }

    /// Adopt an ALREADY-SORTED list (the shape `setgroups(2)` installs after
    /// `groups_sort`), sharing the allocation rather than copying it.
    /// # C: O(1)
    pub fn from_sorted(gids: Arc<[u32]>) -> Self {
        if gids.is_empty() { return Self(None); }
        Self(Some(gids))
    }

    /// Build from an arbitrary slice, sorting it as `groups_sort` does.
    /// # C: O(n log n)
    pub fn from_slice(gids: &[u32]) -> Self {
        if gids.is_empty() { return Self(None); }
        let mut sorted: Vec<u32> = gids.to_vec();
        sorted.sort_unstable();
        Self(Some(Arc::from(sorted.as_slice())))
    }

    /// Ascending-sorted gids. # C: O(1)
    pub fn as_slice(&self) -> &[u32] { self.0.as_deref().unwrap_or(&[]) }

    /// Linux `group_info->ngroups`. # C: O(1)
    pub fn len(&self) -> usize { self.as_slice().len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Linux `groups_search`: binary search over the sorted set.
    /// # C: O(log n)
    pub fn contains(&self, gid: u32) -> bool { self.as_slice().binary_search(&gid).is_ok() }
}

impl PartialEq for GroupList {
    /// # C: O(n)
    fn eq(&self, other: &Self) -> bool { self.as_slice() == other.as_slice() }
}
impl Eq for GroupList {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_slice_sorts_and_membership_uses_binary_search() {
        let list = GroupList::from_slice(&[90, 10, 50]);
        assert_eq!(list.as_slice(), &[10, 50, 90]);
        assert!(list.contains(50));
        assert!(!list.contains(51));
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn the_empty_set_allocates_nothing_and_contains_nothing() {
        let list = GroupList::empty();
        assert!(list.is_empty());
        assert!(!list.contains(0));
        assert_eq!(GroupList::from_slice(&[]).as_slice(), &[] as &[u32]);
    }

    #[test]
    fn equality_compares_the_gid_sets_not_the_allocations() {
        assert_eq!(GroupList::from_slice(&[3, 1]), GroupList::from_slice(&[1, 3]));
        assert_ne!(GroupList::from_slice(&[1]), GroupList::from_slice(&[2]));
    }

    #[test]
    fn a_clone_shares_the_allocation() {
        let list = GroupList::from_slice(&[1, 2, 3]);
        let copy = list.clone();
        assert_eq!(list.as_slice().as_ptr(), copy.as_slice().as_ptr());
    }
}
