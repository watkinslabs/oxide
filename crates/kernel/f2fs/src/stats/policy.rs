//! When a write may land back on the block it came from.
//!
//! Overwriting in place bends the one rule the format is built on — that the
//! previous checkpoint's blocks all survive until the next one retires them —
//! and is worth it only for a file's own DATA, where a roll-forward replay can
//! reconstruct the tail. Which states a mount does it in is a policy, decided
//! in `crate::place::ipu` and reported here as a set rather than a single
//! choice, because several can be armed at once.

use alloc::string::String;

/// The policies, by bit position, and the names they are reported under.
///
/// Re-exported rather than restated: the set the writer CONSULTS is the set the
/// report names, and two lists would be two places for a policy to be armed in
/// one and missing from the other.
pub use crate::place::bits as ipu;

/// The names, indexed by bit position.
pub const IPU_NAMES: [&str; ipu::MAX as usize] = ipu::NAMES;

/// Whether in-place update is off entirely. # C: O(1)
pub fn ipu_disabled(policy: u32) -> bool { policy == ipu::DISABLE }

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
