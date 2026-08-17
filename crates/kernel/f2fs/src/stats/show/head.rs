//! The banner, the on-medium layout, the policy and what the volume holds.

use alloc::format;
use alloc::string::String;

use crate::flags::{CP_DISABLED_FLAG, CP_ERROR_FLAG};
use crate::stats::policy;
use crate::stats::sample::General;

/// What the banner says about the checkpoint's own health.
///
/// Three states, and the order they are tested in is the contract: a mount
/// with checkpointing switched off is reported that way even when the
/// checkpoint also carries the error bit, because the disabled state is the
/// one that explains the other numbers.
/// # C: O(1)
pub fn cp_state(cp_flags: u32) -> &'static str {
    if cp_flags & CP_DISABLED_FLAG != 0 { "Disabled" }
    else if cp_flags & CP_ERROR_FLAG != 0 { "Error" }
    else { "Good" }
}

/// # C: O(N flags + N policies)
pub fn render(o: &mut String, g: &General, dev: &str, index: usize, now: u64) {
    let rw = if g.writable { "RW" } else { "RO" };
    o.push_str(&format!("\n=====[ partition info({dev}). #{index}, {rw}, CP: {}]=====\n",
                        cp_state(g.cp_flags)));
    o.push_str(&policy::sbi_flag_text(g.sbi_flags));
    o.push_str(&format!("[SB: 1] [CP: 2] [SIT: {}] [NAT: {}] ", g.sit_area_segs, g.nat_area_segs));
    o.push_str(&format!("[SSA: {}] [MAIN: {}", g.ssa_area_segs, g.main_area_segs));
    o.push_str(&format!("(OverProv:{} Resv:{})]\n\n", g.overp_segs, g.rsvd_segs));
    o.push_str(&format!("Current Time Sec: {} / Mounted Time Sec: {}\n\n", now, g.mounted_time));

    o.push_str("Policy:\n");
    o.push_str("  - IPU: [");
    o.push_str(&policy::ipu_text(g.ipu_policy));
    o.push_str(" ]\n\n");

    if g.discard {
        o.push_str(&format!("Utilization: {}% ({} valid blocks, {} discard blocks)\n",
                            g.utilization, g.valid_count, g.discard_blks));
    } else {
        o.push_str(&format!("Utilization: {}% ({} valid blocks)\n",
                            g.utilization, g.valid_count));
    }

    o.push_str(&format!("  - Node: {} (Inode: {}, ", g.valid_node_count, g.valid_inode_count));
    o.push_str(&format!("Other: {})\n  - Data: {}\n", g.other_nodes(), g.data_blocks()));
    o.push_str(&format!("  - Inline_xattr Inode: {}\n", g.inline_xattr));
    o.push_str(&format!("  - Inline_data Inode: {}\n", g.inline_inode));
    o.push_str(&format!("  - Inline_dentry Inode: {}\n", g.inline_dir));
    o.push_str(&format!("  - Compressed Inode: {}, Blocks: {}\n", g.compr_inode, g.compr_blocks));
    o.push_str(&format!("  - Swapfile Inode: {}\n", g.swapfile_inode));
    o.push_str(&format!("  - Donate Inode: {}\n", g.ndonate_files));
    o.push_str(&format!("  - Orphan/Append/Update Inode: {}, {}, {}\n",
                        g.orphans, g.append, g.update));
}
