//! Where the user's blocks are, how they were written, and what the mount
//! costs in memory.

use alloc::format;
use alloc::string::String;

use crate::stats::counters::alloc_of;
use crate::stats::sample::General;

/// # C: O(1)
pub fn render(o: &mut String, g: &General) {
    // A bar rather than three numbers: the question the figure answers is
    // what proportion of the volume is in each state, and a bar is read at a
    // glance where three percentages are not. Fiftieths, so all three fit.
    o.push_str("\nDistribution of User Blocks:");
    o.push_str(" [ valid | invalid | free ]\n");
    o.push_str("  [");
    bar(o, g.util_valid);
    o.push('|');
    bar(o, g.util_invalid);
    o.push('|');
    bar(o, g.util_free);
    o.push_str("]\n\n");

    o.push_str(&format!("IPU: {} blocks\n", g.inplace_count));
    o.push_str(&format!("SSR: {} blocks in {} segments\n",
                        g.block_count[alloc_of::SSR], g.segment_count[alloc_of::SSR]));
    o.push_str(&format!("LFS: {} blocks in {} segments\n",
                        g.block_count[alloc_of::LFS], g.segment_count[alloc_of::LFS]));

    o.push_str(&format!("\nBDF: {}, avg. vblocks: {}\n", g.bimodal, g.avg_vblocks));

    o.push_str(&format!("\nMemory: {} KB\n", g.mem_total_kb()));
    o.push_str(&format!("  - static: {} KB\n", g.mem.base_mem >> 10));
    o.push_str(&format!("  - cached all: {} KB\n", g.mem.cache_mem >> 10));
    o.push_str(&format!("  - read extent cache: {} KB\n", g.mem.ext_mem[0] >> 10));
    o.push_str(&format!("  - block age extent cache: {} KB\n", g.mem.ext_mem[1] >> 10));
    o.push_str(&format!("  - paged : {} KB\n", g.mem.page_mem >> 10));
}

/// One share of the bar. A negative share draws nothing: the three shares are
/// derived from each other, so one can come out below zero on a volume whose
/// counts moved between the reads that produced them, and a loop over a
/// negative count is the one outcome that must not happen.
/// # C: O(share)
fn bar(o: &mut String, share: i64) {
    for _ in 0..share.max(0) { o.push('-'); }
}
