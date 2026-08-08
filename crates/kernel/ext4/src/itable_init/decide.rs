// What lazy inode-table initialisation decides, with no device, no clock and
// no mounted filesystem behind it.
//
// UNGATED on purpose: every judgement the initialiser makes about which bytes
// it may overwrite is here, where `cargo test` reaches it. Getting this wrong
// destroys live inodes, so it is the part that must be checkable directly.

/// The shape of one group's inode table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableGeometry {
    /// Inodes in every group.
    pub inodes_per_group: u32,
    /// Inodes that fit in one filesystem block.
    pub inodes_per_block: u32,
    /// Filesystem blocks one group's inode table occupies.
    pub blocks_per_table: u32,
}

impl TableGeometry {
    /// Derive the geometry from the superblock's own numbers. A degenerate
    /// filesystem (an inode larger than a block, or either size zero) yields a
    /// table of no blocks, which the initialiser then has nothing to zero in.
    /// # C: O(1)
    pub fn new(inodes_per_group: u32, block_size: u32, inode_size: u16) -> Self {
        let per_block = if inode_size == 0 { 0 } else { block_size / inode_size as u32 };
        let blocks = if per_block == 0 { 0 } else { inodes_per_group.div_ceil(per_block) };
        Self { inodes_per_group, inodes_per_block: per_block, blocks_per_table: blocks }
    }
}

/// How many blocks at the START of the table may hold live inodes and must not
/// be touched.
///
/// A group whose inode bitmap was never materialised has no live inodes at all,
/// so its whole table may be zeroed. Otherwise the live inodes are the ones the
/// unused counter does NOT cover, and they occupy whole blocks from the front.
/// `None` means the descriptor's counters are inconsistent with the group's own
/// size — the caller must then zero nothing rather than guess.
/// # C: O(1)
pub fn used_itable_blocks(geom: &TableGeometry, itable_unused: u32, inode_uninit: bool)
    -> Option<u32>
{
    if inode_uninit { return Some(0); }
    if itable_unused > geom.inodes_per_group { return None; }
    if geom.inodes_per_block == 0 { return Some(0); }
    let used_inodes = geom.inodes_per_group - itable_unused;
    let used = used_inodes.div_ceil(geom.inodes_per_block);
    if used > geom.blocks_per_table { return None; }
    Some(used)
}

/// The first group at or after `from` whose table still needs zeroing.
/// # C: O(groups - from)
pub fn next_unzeroed_group(from: u32, groups: u32, zeroed: impl Fn(u32) -> bool) -> Option<u32> {
    (from..groups).find(|g| !zeroed(*g))
}

/// How long to leave the device alone after a group that took `elapsed_ns`.
///
/// The wait is a MULTIPLE of the work, not a constant: a slow device pauses
/// proportionally longer, so lazy initialisation costs the same fraction of the
/// device's throughput whatever the device is. That fraction is what
/// `init_itable=` names.
/// # C: O(1)
pub fn wait_after_group_ns(elapsed_ns: u64, li_wait_mult: u32) -> u64 {
    elapsed_ns.saturating_mul(li_wait_mult as u64)
}

/// Whether a group may be initialised now, given when the last one finished and
/// how long that one earned. An initialiser that has not run yet (`None`) may
/// start immediately.
/// # C: O(1)
pub fn is_due(last_ns: Option<u64>, wait_ns: u64, now_ns: u64) -> bool {
    let Some(last) = last_ns else { return true };
    let Some(age) = now_ns.checked_sub(last) else { return false };
    age >= wait_ns
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geom(inodes_per_group: u32, inodes_per_block: u32) -> TableGeometry {
        TableGeometry {
            inodes_per_group, inodes_per_block,
            blocks_per_table: inodes_per_group.div_ceil(inodes_per_block),
        }
    }

    /// A group whose inode bitmap was never materialised holds no inodes, so
    /// the whole table is free to zero.
    #[test]
    fn an_untouched_group_may_be_zeroed_whole() {
        assert_eq!(used_itable_blocks(&geom(8192, 16), 8192, true), Some(0));
        assert_eq!(used_itable_blocks(&geom(8192, 16), 0, true), Some(0),
            "an untouched group's unused counter does not matter");
    }

    /// A group that HAS been used keeps the blocks its live inodes occupy, and
    /// they are counted from the front in whole blocks.
    #[test]
    fn a_used_group_keeps_the_blocks_its_inodes_occupy() {
        let g = geom(8192, 16);
        assert_eq!(used_itable_blocks(&g, 8192, false), Some(0), "none used yet");
        assert_eq!(used_itable_blocks(&g, 8191, false), Some(1), "one inode holds one block");
        assert_eq!(used_itable_blocks(&g, 8192 - 16, false), Some(1), "exactly one block's worth");
        assert_eq!(used_itable_blocks(&g, 8192 - 17, false), Some(2), "one inode into the second");
        assert_eq!(used_itable_blocks(&g, 0, false), Some(g.blocks_per_table), "all of it");
    }

    /// A counter claiming more unused inodes than the group has is refused
    /// rather than believed: believing it would zero blocks holding live
    /// inodes, which is the one failure this decision exists to prevent.
    #[test]
    fn an_impossible_unused_count_is_refused() {
        assert_eq!(used_itable_blocks(&geom(8192, 16), 8193, false), None);
        assert_eq!(used_itable_blocks(&geom(8192, 16), u32::MAX, false), None);
    }

    /// A table shorter than its own inode count implies would zero past its
    /// end; refuse that too.
    #[test]
    fn a_table_too_short_for_its_inodes_is_refused() {
        let bad = TableGeometry { inodes_per_group: 8192, inodes_per_block: 16, blocks_per_table: 4 };
        assert_eq!(used_itable_blocks(&bad, 0, false), None);
    }

    /// The walk finds the first group that still needs work, and answers
    /// nothing once every group from there on is done.
    #[test]
    fn the_walk_finds_the_next_group_that_needs_work() {
        let done = [true, true, false, true, false];
        let f = |g: u32| done[g as usize];
        assert_eq!(next_unzeroed_group(0, 5, f), Some(2));
        assert_eq!(next_unzeroed_group(3, 5, f), Some(4));
        assert_eq!(next_unzeroed_group(5, 5, f), None);
        assert_eq!(next_unzeroed_group(0, 0, f), None);
    }

    /// The wait is the work times the multiplier, which is what makes the
    /// option a fraction of the device rather than a fixed delay.
    #[test]
    fn the_wait_is_a_multiple_of_the_work() {
        assert_eq!(wait_after_group_ns(1_000, 10), 10_000);
        assert_eq!(wait_after_group_ns(1_000, 0), 0, "a zero multiplier does not pause");
        assert_eq!(wait_after_group_ns(u64::MAX, 10), u64::MAX, "and it does not wrap");
    }

    /// An initialiser that has never run starts at once; one that has waits out
    /// its earned pause, and a clock that went backwards does not restart it.
    #[test]
    fn the_pause_is_waited_out_before_the_next_group() {
        assert!(is_due(None, 10_000, 0));
        assert!(!is_due(Some(0), 10_000, 9_999));
        assert!(is_due(Some(0), 10_000, 10_000));
        assert!(!is_due(Some(10_000), 10_000, 5_000));
    }

    /// The geometry follows the filesystem's own sizes, so a filesystem with
    /// bigger inodes has a proportionally bigger table.
    #[test]
    fn the_geometry_follows_the_filesystem_sizes() {
        let g = TableGeometry::new(8192, 4096, 256);
        assert_eq!(g.inodes_per_block, 16);
        assert_eq!(g.blocks_per_table, 512);
        assert_eq!(TableGeometry::new(8192, 4096, 128).blocks_per_table, 256);
        assert_eq!(TableGeometry::new(8192, 1024, 256).blocks_per_table, 2048);
    }

    /// A filesystem whose inodes do not fit a block leaves nothing to zero
    /// rather than dividing by zero.
    #[test]
    fn a_degenerate_geometry_yields_an_empty_table() {
        assert_eq!(TableGeometry::new(8192, 1024, 0).blocks_per_table, 0);
        assert_eq!(TableGeometry::new(8192, 128, 256).blocks_per_table, 0);
        assert_eq!(used_itable_blocks(&TableGeometry::new(8192, 128, 256), 0, false), Some(0),
            "a table of no blocks has no live blocks to keep and none to zero");
    }
}
