//! `discard_plist_info` — the pending-discard queue, by request length.
//!
//! A discard request covers a RUN of consecutive blocks, and the queue is
//! bucketed by how long that run is: short runs are the expensive ones, and
//! seeing where the queue's mass sits is what the report is for. Bucket `i`
//! holds runs of `i + 1` blocks, and the last bucket holds every run at or
//! above its length.
//!
//! Eight buckets per line, each either its count or a dot for empty, which is
//! what makes a sparse queue readable at a glance.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fsattr::Attr;
use crate::mount::F2fs;
use crate::volume::discard::coalesce;

/// Buckets the queue is reported in.
pub const MAX_PLIST_NUM: usize = 512;

/// Buckets per line of the report.
const PER_LINE: usize = 8;

/// Which bucket a run of `len` blocks falls in. A run at or past the last
/// bucket's length lands in it, so the report has a fixed width whatever the
/// queue holds. # C: O(1)
pub fn plist_idx(len: u32) -> usize {
    let len = len as usize;
    if len >= MAX_PLIST_NUM { MAX_PLIST_NUM - 1 } else { len.saturating_sub(1) }
}

/// The report, from the runs currently queued.
///
/// `enabled` is whether this mount announces discards at all: upstream prints
/// the header and stops when it does not, because the queue then means
/// nothing rather than being empty.
/// # C: O(N runs + buckets)
pub fn discard_plist_body(enabled: bool, runs: &[(u32, u32)]) -> String {
    let mut s = String::from(
        "Discard pend list(Show diacrd_cmd count on each entry, .:not exist):\n");
    if !enabled { return s; }
    let mut counts = alloc::vec![0u32; MAX_PLIST_NUM];
    for (_, len) in runs { counts[plist_idx(*len)] += 1; }
    for i in 0..MAX_PLIST_NUM {
        if i % PER_LINE == 0 { s.push_str(&format!("  {:<3}", i)); }
        if counts[i] != 0 { s.push_str(&format!(" {:7}", counts[i])); }
        else { s.push_str("       ."); }
        if i % PER_LINE == PER_LINE - 1 { s.push('\n'); }
    }
    s.push('\n');
    s
}

/// # C: O(N pending log N)
pub(crate) fn file(fs: &Arc<F2fs>, dev: &str) -> Attr {
    let fs = Arc::clone(fs);
    Attr::ro(dev, "discard_plist_info", Arc::new(move || {
        let (enabled, runs): (bool, Vec<(u32, u32)>) = {
            let v = fs.volume.lock();
            (v.discards(), coalesce(v.pending_discard.clone()))
        };
        Ok(discard_plist_body(enabled, &runs).into_bytes())
    }))
}
