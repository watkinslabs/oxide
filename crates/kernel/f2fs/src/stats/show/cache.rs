//! The extent caches, and everything the mount still owes the device.

use alloc::format;
use alloc::string::String;

use crate::stats::counters::extent_of;
use crate::stats::sample::General;

/// # C: O(1)
pub fn render(o: &mut String, g: &General) {
    // Three ways a read-extent lookup can be answered: from the one extent
    // the inode carries, from the per-inode cache, and from the shared tree.
    o.push_str("\nExtent Cache (Read):\n");
    o.push_str(&format!("  - Hit Count: L1-1:{} L1-2:{} L2:{}\n",
                        g.hit_largest, g.hit_cached[extent_of::READ],
                        g.hit_rbtree[extent_of::READ]));
    o.push_str(&format!("  - Hit Ratio: {}% ({} / {})\n",
                        g.hit_ratio(extent_of::READ), g.hit_total[extent_of::READ],
                        g.total_ext[extent_of::READ]));
    o.push_str(&format!("  - Inner Struct Count: tree: {}({}), node: {}\n", 0, 0, 0));

    o.push_str("\nExtent Cache (Block Age):\n");
    o.push_str(&format!("  - Allocated Data Blocks: {}\n", g.allocated_data_blocks));
    o.push_str(&format!("  - Hit Count: L1:{} L2:{}\n",
                        g.hit_cached[extent_of::BLOCK_AGE], g.hit_rbtree[extent_of::BLOCK_AGE]));
    o.push_str(&format!("  - Hit Ratio: {}% ({} / {})\n",
                        g.hit_ratio(extent_of::BLOCK_AGE), g.hit_total[extent_of::BLOCK_AGE],
                        g.total_ext[extent_of::BLOCK_AGE]));
    o.push_str(&format!("  - Inner Struct Count: tree: {}({}), node: {}\n", 0, 0, 0));

    // Work in flight. Every one of these counts requests the volume has
    // handed to a lower layer and is still waiting on. This build's reads and
    // writes complete before the call that made them returns, so nothing is
    // ever outstanding at the moment of a read — a zero here means the mount
    // owes the device nothing, which is always true of a synchronous writer.
    o.push_str("\nBalancing F2FS Async:\n");
    o.push_str(&format!("  - DIO (R: {:>4}, W: {:>4})\n", 0, 0));
    o.push_str(&format!("  - IO_R (Data: {:>4}, Node: {:>4}, Meta: {:>4}\n", 0, 0, 0));
    o.push_str(&format!("  - IO_W (CP: {:>4}, Data: {:>4}, Flush: ({:>4} {:>4} {:>4}), ",
                        0, 0, 0, 0, 1));
    o.push_str(&format!("Discard: ({:>4} {:>4})) cmd: {:>4} undiscard:{:>4}\n",
                        0, 0, 0, g.undiscard_blks));
    o.push_str(&format!("  - atomic IO: {:>4} (Max. {:>4})\n", g.aw_cnt, g.max_aw_cnt));
    o.push_str(&format!("  - compress: {:>4}, hit:{:>8}\n", 0, 0));
    o.push_str(&format!("  - nodes: {:>4} in {:>4}\n", 0, 0));
    o.push_str(&format!("  - dents: {:>4} in dirs:{:>4} ({:>4})\n",
                        0, g.ndirty_dirs, g.ndirty_all));
    o.push_str(&format!("  - data: {:>4} in files:{:>4}\n", 0, g.ndirty_files));
    o.push_str(&format!("  - quota data: {:>4} in quota files:{:>4}\n", 0, g.nquota_files));
    o.push_str(&format!("  - meta: {:>4} in {:>4}\n", 0, 0));
    o.push_str(&format!("  - imeta: {:>4}\n", 0));
    o.push_str(&format!("  - fsync mark: {:>4}\n", 0));
    o.push_str(&format!("  - NATs: {:>9}/{:>9}\n  - SITs: {:>9}/{:>9}\n",
                        g.dirty_nats, g.nats, g.dirty_sits, g.sits));
    o.push_str(&format!("  - free_nids: {:>9}/{:>9}\n  - alloc_nids: {:>9}\n",
                        g.free_nids, g.avail_nids, g.alloc_nids));
}
