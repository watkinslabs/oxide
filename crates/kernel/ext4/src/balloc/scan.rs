// `mb_optimize_scan=` — the order the block allocator visits block groups in.
//
// UNGATED: the option changes nothing else, so the order IS the option, and it
// is decided here where `cargo test` can drive it without a device.

/// Group count from which the allocator stops scanning groups in plain group
/// order by default. Below it a linear walk visits every group cheaply; above
/// it, a filesystem whose early groups are full makes that walk pay for its
/// whole length on every allocation.
pub const LINEAR_SCAN_THRESHOLD: u32 = 16;

/// Whether a filesystem of `groups` groups scans in free-space order when the
/// mount named no preference. # C: O(1)
pub fn optimize_scan_default(groups: u32) -> bool { groups >= LINEAR_SCAN_THRESHOLD }

/// Return the largest power-of-two free order represented by a bitmap.
/// The summary is advisory; the bitmap remains the allocation authority.
/// # C: O(max_bits)
pub fn largest_free_order(bitmap: &[u8], max_bits: u32) -> Option<u8> {
    let mut best = 0u32;
    let mut run = 0u32;
    for bit in 0..max_bits {
        if bitmap[bit as usize >> 3] & (1u8 << (bit & 7)) == 0 { run += 1; }
        else { best = best.max(run); run = 0; }
    }
    best = best.max(run);
    if best == 0 { return None; }
    Some((u32::BITS - 1 - best.leading_zeros()) as u8)
}

/// Return Linux mballoc's average-fragment xarray order for `len`.
/// This mirrors `mb_avg_fragment_size_order()`: `fls(len) - 2`, with
/// one-block fragments in order zero. # C: O(1)
pub fn fragment_order_for_len(len: u32) -> u8 {
    if len <= 1 { return 0; }
    (u32::BITS - 1 - len.leading_zeros()).saturating_sub(1) as u8
}

/// Return Linux mballoc's order for the average free-fragment size.
/// `bb_free / bb_fragments` is classified by the same `fls(len) - 2`
/// function used by the reference implementation; groups with no free
/// fragment have no entry. # C: O(max_bits)
pub fn average_fragment_order(bitmap: &[u8], max_bits: u32) -> Option<u8> {
    let mut free = 0u32;
    let mut fragments = 0u32;
    let mut in_free = false;
    for bit in 0..max_bits {
        let clear = bitmap[bit as usize >> 3] & (1u8 << (bit & 7)) == 0;
        if clear {
            free += 1;
            if !in_free { fragments += 1; in_free = true; }
        } else {
            in_free = false;
        }
    }
    if fragments == 0 { return None; }
    let average = free / fragments;
    Some(fragment_order_for_len(average))
}

/// Replace one group's membership in an order-indexed summary. This is the
/// BTree equivalent of Linux's xarray erase/insert update.
pub fn replace_order_index(
    index: &mut alloc::collections::BTreeMap<u8, alloc::collections::BTreeSet<u32>>,
    group: u32,
    old: Option<u8>,
    new: Option<u8>,
) {
    if let Some(order) = old {
        let empty = if let Some(groups) = index.get_mut(&order) {
            groups.remove(&group);
            groups.is_empty()
        } else { false };
        if empty { index.remove(&order); }
    }
    if let Some(order) = new {
        index.entry(order).or_default().insert(group);
    }
}

/// The group the scan STARTS at.
///
/// The plain order starts at the caller's locality hint and walks forward, so
/// a file's blocks stay near its inode. Free-space order starts at the group
/// with the most free blocks instead, which is the group most likely to satisfy
/// the request without the walk touching every full group before it — the cost
/// the option exists to remove. Either way the walk continues around every
/// group, so the answer is the same whenever any group has a free block; only
/// how quickly it is reached, and how the file is laid out, differ.
///
/// A `freest` group with nothing free is not preferred: on a filesystem with no
/// free space at all it would only move the futile scan's starting point.
/// # C: O(1)
pub fn scan_start(hint: u32, groups: u32, optimize: bool, freest: Option<(u32, u64)>) -> u32 {
    if groups == 0 { return 0; }
    if optimize {
        if let Some((g, free)) = freest {
            if free > 0 && g < groups { return g; }
        }
    }
    hint % groups
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small filesystem keeps the plain walk; a large one does not. The
    /// threshold is where a linear scan of full groups starts to dominate.
    #[test]
    fn the_default_follows_the_filesystems_size() {
        assert!(!optimize_scan_default(1));
        assert!(!optimize_scan_default(LINEAR_SCAN_THRESHOLD - 1));
        assert!(optimize_scan_default(LINEAR_SCAN_THRESHOLD));
        assert!(optimize_scan_default(1024));
    }

    /// Plain order starts where the caller asked, which is what keeps a file's
    /// blocks near its inode.
    #[test]
    fn the_plain_order_starts_at_the_locality_hint() {
        assert_eq!(scan_start(3, 8, false, Some((7, 1000))), 3);
        assert_eq!(scan_start(11, 8, false, None), 3, "the hint wraps");
    }

    /// Free-space order starts at the emptiest group instead — the option's
    /// entire observable effect.
    #[test]
    fn free_space_order_starts_at_the_emptiest_group() {
        assert_eq!(scan_start(3, 8, true, Some((6, 5000))), 6);
    }

    /// An emptiest group with nothing in it is not a better place to start
    /// than the hint: on a full filesystem both scans fail, and the hint at
    /// least keeps the locality.
    #[test]
    fn a_full_filesystem_keeps_the_hint() {
        assert_eq!(scan_start(3, 8, true, Some((6, 0))), 3);
        assert_eq!(scan_start(3, 8, true, None), 3);
    }

    /// A group number outside the filesystem is refused rather than used —
    /// the scan must start somewhere that exists.
    #[test]
    fn a_group_outside_the_filesystem_is_not_a_start() {
        assert_eq!(scan_start(3, 8, true, Some((9, 5000))), 3);
        assert_eq!(scan_start(3, 0, true, Some((0, 5000))), 0);
    }

    #[test]
    fn largest_free_order_tracks_the_buddy_summary() {
        assert_eq!(largest_free_order(&[0b1111_0000], 8), Some(2));
        assert_eq!(largest_free_order(&[0b1111_1111], 8), None);
        assert_eq!(largest_free_order(&[0], 3), Some(1));
    }

    #[test]
    fn average_fragment_order_matches_linux_buckets() {
        assert_eq!(average_fragment_order(&[0], 8), Some(2));
        assert_eq!(average_fragment_order(&[0b1111_0000], 8), Some(1));
        assert_eq!(average_fragment_order(&[0b1010_1010], 8), Some(0));
        assert_eq!(average_fragment_order(&[0xff], 8), None);
    }

    #[test]
    fn fragment_order_matches_reference_fls_minus_two() {
        assert_eq!(fragment_order_for_len(0), 0);
        assert_eq!(fragment_order_for_len(1), 0);
        assert_eq!(fragment_order_for_len(2), 0);
        assert_eq!(fragment_order_for_len(3), 0);
        assert_eq!(fragment_order_for_len(4), 1);
        assert_eq!(fragment_order_for_len(7), 1);
        assert_eq!(fragment_order_for_len(8), 2);
    }

    #[test]
    fn replacing_an_order_removes_stale_membership() {
        let mut index = alloc::collections::BTreeMap::new();
        replace_order_index(&mut index, 3, None, Some(1));
        replace_order_index(&mut index, 3, Some(1), Some(4));
        assert!(!index.get(&1).is_some_and(|groups| groups.contains(&3)));
        assert_eq!(index.get(&4).map(|groups| groups.iter().copied().collect::<alloc::vec::Vec<_>>()), Some(alloc::vec![3]));
        replace_order_index(&mut index, 3, Some(4), None);
        assert!(index.is_empty());
    }
}
