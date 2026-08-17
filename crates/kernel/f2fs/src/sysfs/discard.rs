//! `/sys/fs/f2fs/<dev>/stat/` — what the discard thread has done.
//!
//! The two counters live here rather than in `stat` next door because they are
//! the THREAD's, not the volume's: both come off the discard control block
//! under its own lock, and neither needs the volume lock a `stat` reader takes.
//! Keeping them apart is what stops a counter read from waiting behind a block
//! fetch.
//!
//! Both were absent until this module existed, on the stated grounds that this
//! build announced discards inline from the checkpoint path and had no thread
//! to have issued or queued anything. That has not been true for some time: the
//! thread exists, it issues runs in either length-first or address order, and it
//! keeps both counts.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fsattr::{line_u64, Attr};
use crate::mount::F2fs;

/// A read-only counter off the discard control block.
///
/// The lock is taken for the read and released before the bytes leave, the same
/// rule every other attribute here follows.
/// # C: O(f)
fn counter(fs: &Arc<F2fs>, dir: &str, name: &'static str,
           f: fn(&crate::bg::discard::DiscardControl) -> u64) -> Attr {
    let fs = Arc::clone(fs);
    Attr::ro(dir, name, Arc::new(move || {
        let value = { f(&fs.bg().dcc.lock()) };
        Ok(line_u64(value))
    }))
}

/// The discard thread's two counters. # C: O(1)
pub(crate) fn attrs(fs: &Arc<F2fs>, dev: &str) -> Vec<Attr> {
    let dir = alloc::format!("{dev}/stat");
    alloc::vec![
        // Runs handed to a device since the mount. Monotonic: a report of work
        // done, which a count that could fall would not be.
        counter(fs, &dir, "issued_discard", |d| d.issued),
        // Runs handed to a device whose erase has not come back. Distinct from
        // the parked count `pending_discard` reports: a run is parked, or it is
        // in flight, and reporting the parked ones here would tell a tool the
        // device was working on requests it has already answered for.
        counter(fs, &dir, "queued_discard", |d| d.queued_count()),
    ]
}
