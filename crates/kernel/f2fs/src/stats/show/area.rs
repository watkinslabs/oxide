//! Where each open log is writing, and how the segments behind them stand.

use alloc::format;
use alloc::string::String;

use crate::stats::sample::General;
use crate::uapi::{CURSEG_ALL_DATA_ATGC, CURSEG_COLD_DATA, CURSEG_COLD_DATA_PINNED,
                  CURSEG_COLD_NODE, CURSEG_HOT_DATA, CURSEG_HOT_NODE, CURSEG_WARM_DATA,
                  CURSEG_WARM_NODE};

/// The rows, in the order the report lists them — coldest data first, then
/// the three node logs. The order is the report's, not the numbering's.
const ROWS: [(&str, usize); 6] = [
    ("COLD   data", CURSEG_COLD_DATA),
    ("WARM   data", CURSEG_WARM_DATA),
    ("HOT    data", CURSEG_HOT_DATA),
    ("Dir   dnode", CURSEG_HOT_NODE),
    ("File  dnode", CURSEG_WARM_NODE),
    ("Indir nodes", CURSEG_COLD_NODE),
];

/// # C: O(1)
pub fn render(o: &mut String, g: &General) {
    o.push_str(&format!("\nMain area: {} segs, {} secs {} zones\n",
                        g.main_area_segs, g.main_area_sections, g.main_area_zones));
    o.push_str(&format!("    TYPE         {:>8} {:>8} {:>8} {:>8} {:>10} {:>10} {:>10}\n",
                        "blkoff", "segno", "secno", "zoneno",
                        "dirty_seg", "full_seg", "valid_blk"));
    for (name, i) in ROWS {
        o.push_str(&format!("  - {}: {:>8} {:>8} {:>8} {:>8} {:>10} {:>10} {:>10}\n",
                            name, g.blkoff[i], g.curseg[i], g.cursec[i], g.curzone[i],
                            g.dirty_seg[i], g.full_seg[i], g.valid_blks[i]));
    }
    // The pinned log exists only while the volume is mounted, so it has no
    // occupancy columns — it is reported by position alone.
    let p = CURSEG_COLD_DATA_PINNED;
    o.push_str(&format!("  - Pinned file: {:>8} {:>8} {:>8} {:>8}\n",
                        g.blkoff[p], g.curseg[p], g.cursec[p], g.curzone[p]));
    // The age-threshold cleaner's own log, which exists only while mounted and
    // only on a volume old enough for the policy to mean anything — so it too
    // is reported by position alone.
    let a = CURSEG_ALL_DATA_ATGC;
    o.push_str(&format!("  - ATGC   data: {:>8} {:>8} {:>8} {:>8}\n",
                        g.blkoff[a], g.curseg[a], g.cursec[a], g.curzone[a]));

    o.push_str(&format!("\n  - Valid: {}\n  - Dirty: {}\n", g.valid_segs(), g.dirty_count));
    o.push_str(&format!("  - Prefree: {}\n  - Free: {} ({})\n\n",
                        g.prefree_count, g.free_segs, g.free_secs));
}
