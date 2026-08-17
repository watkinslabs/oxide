//! What checkpointing and cleaning have done since the mount.

use alloc::format;
use alloc::string::String;

use crate::stats::counters::{call, gc_mode, gc_of, gc_when, meta};
use crate::stats::sample::General;

/// The reclaimed-segment rows, in the order the report lists them — which is
/// not the order the policies are numbered in.
const RECLAIMED: [(&str, usize); 7] = [
    ("Normal", gc_mode::NORMAL),
    ("Idle CB", gc_mode::IDLE_CB),
    ("Idle Greedy", gc_mode::IDLE_GREEDY),
    ("Idle AT", gc_mode::IDLE_AT),
    ("Urgent High", gc_mode::URGENT_HIGH),
    ("Urgent Mid", gc_mode::URGENT_MID),
    ("Urgent Low", gc_mode::URGENT_LOW),
];

/// # C: O(1)
pub fn render(o: &mut String, g: &General) {
    o.push_str(&format!("CP calls: {} (BG: {})\n",
                        g.cp_call_count[call::TOTAL], g.cp_call_count[call::BACKGROUND]));
    o.push_str(&format!("CP count: {}\n", g.cp_count));
    o.push_str(&format!("  - cp blocks : {}\n", g.meta_count[meta::CP]));
    o.push_str(&format!("  - sit blocks : {}\n", g.meta_count[meta::SIT]));
    o.push_str(&format!("  - nat blocks : {}\n", g.meta_count[meta::NAT]));
    o.push_str(&format!("  - ssa blocks : {}\n", g.meta_count[meta::SSA]));
    // The merge figures describe a thread that batches checkpoint requests.
    // This build writes each checkpoint on the thread that asked for it, so
    // nothing is ever queued and no request has ever waited: the zeroes are
    // the measurement, not a missing one.
    o.push_str("CP merge:\n");
    o.push_str(&format!("  - Queued : {:>4}\n", 0));
    o.push_str(&format!("  - Issued : {:>4}\n", 0));
    o.push_str(&format!("  - Total : {:>4}\n", 0));
    o.push_str(&format!("  - Cur time : {:>4}(ms)\n", 0));
    o.push_str(&format!("  - Peak time : {:>4}(ms)\n", 0));

    let gc_total = g.gc_call_count[call::BACKGROUND] + g.gc_call_count[call::FOREGROUND];
    o.push_str(&format!("GC calls: {} (gc_thread: {})\n",
                        gc_total, g.gc_call_count[call::BACKGROUND]));
    if g.large_section {
        for (name, of) in [("data", gc_of::DATA), ("node", gc_of::NODE)] {
            o.push_str(&format!("  - {} sections : {} (BG: {})\n", name,
                                g.gc_secs[of][gc_when::BG] + g.gc_secs[of][gc_when::FG],
                                g.gc_secs[of][gc_when::BG]));
        }
    }
    for (name, of) in [("data", gc_of::DATA), ("node", gc_of::NODE)] {
        o.push_str(&format!("  - {} segments : {} (BG: {})\n", name,
                            g.gc_segs[of][gc_when::BG] + g.gc_segs[of][gc_when::FG],
                            g.gc_segs[of][gc_when::BG]));
    }
    o.push_str("  - Reclaimed segs :\n");
    for (name, mode) in RECLAIMED {
        o.push_str(&format!("    - {} : {}\n", name, g.gc_reclaimed_segs[mode]));
    }
    o.push_str(&format!("Try to move {} blocks (BG: {})\n",
                        g.tot_blks, g.bg_data_blks + g.bg_node_blks));
    o.push_str(&format!("  - data blocks : {} ({})\n", g.data_blks, g.bg_data_blks));
    o.push_str(&format!("  - node blocks : {} ({})\n", g.node_blks, g.bg_node_blks));
    o.push_str(&format!("BG skip : IO: {}, Other: {}\n", g.io_skip_bggc, g.other_skip_bggc));
    o.push_str(&format!("defrag blocks : {}\n", g.defrag_blks));
}
