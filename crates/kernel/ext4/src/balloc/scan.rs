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
}
