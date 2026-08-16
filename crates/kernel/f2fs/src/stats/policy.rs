//! When a write may land back on the block it came from.
//!
//! Overwriting in place breaks the one rule the format is built on — that
//! the previous checkpoint's blocks all survive until the next one retires
//! them — so it is only ever done where the block being overwritten is
//! already unreachable from any checkpoint. Which of those cases a mount
//! takes is a policy, reported as a set rather than a single choice because
//! several can be armed at once.

use alloc::string::String;

use crate::opts::Options;

/// The policies, by bit position. The positions are the report's ABI: a
/// reader decodes the set by name, and the names are listed in this order.
pub mod ipu {
    pub const FORCE: u32 = 0;
    pub const SSR: u32 = 1;
    pub const UTIL: u32 = 2;
    pub const SSR_UTIL: u32 = 3;
    pub const FSYNC: u32 = 4;
    pub const ASYNC: u32 = 5;
    pub const NOCACHE: u32 = 6;
    pub const HONOR_OPU_WRITE: u32 = 7;
    pub const MAX: u32 = 8;
}

/// The names, indexed by bit position.
pub const IPU_NAMES: [&str; ipu::MAX as usize] =
    ["FORCE", "SSR", "UTIL", "SSR_UTIL", "FSYNC", "ASYNC", "NOCACHE", "HONOR_OPU_WRITE"];

/// Which policies this mount will use.
///
/// None. Every write this build makes takes a fresh block and releases the
/// old one, with no path that rewrites a block where it sits — so the honest
/// report is the empty set, which the reader renders as disabled. Reporting
/// a policy the writer does not consult would say in-place update is armed
/// on a mount where it can never happen.
/// # C: O(1)
pub fn ipu_policy(_o: &Options) -> u32 { 0 }

/// Whether in-place update is off entirely. # C: O(1)
pub fn ipu_disabled(policy: u32) -> bool { policy == 0 }

/// The set as the report writes it: the armed names, or the word that says
/// there are none. # C: O(N policies)
pub fn ipu_text(policy: u32) -> String {
    if ipu_disabled(policy) { return String::from(" DISABLE"); }
    let mut o = String::new();
    for (bit, name) in IPU_NAMES.iter().enumerate() {
        if policy & (1 << bit) == 0 { continue; }
        o.push(' ');
        o.push_str(name);
    }
    o
}

/// The conditions a mount can be in, by bit position in the status word, and
/// the name each is reported under.
///
/// The positions are the ones the mount's own status attribute publishes, so
/// the two surfaces cannot drift: a bit named here and set there means the
/// same thing.
pub const SBI_FLAG_NAMES: [(u32, &str); 17] = [
    (0, "fs_dirty"), (1, "closing"), (2, "need_fsck"), (3, "recovering"),
    (4, "sb_dirty"), (5, "need_cp"), (6, "shutdown"), (7, "recovered"),
    (8, "cp_disabled"), (9, "cp_disabled_quick"), (10, "quota_need_flush"),
    (11, "quota_skip_flush"), (12, "quota_need_repair"), (13, "resizefs"),
    (14, "freezefs"), (15, "writable"), (16, "enable_checkpoint"),
];

/// The bracketed list of conditions, or nothing when none is set.
/// # C: O(N flags)
pub fn sbi_flag_text(word: u64) -> String {
    if word == 0 { return String::new(); }
    let mut o = String::from("[SBI:");
    for (bit, name) in SBI_FLAG_NAMES {
        if word & (1u64 << bit) == 0 { continue; }
        o.push(' ');
        o.push_str(name);
    }
    o.push_str("]\n");
    o
}
