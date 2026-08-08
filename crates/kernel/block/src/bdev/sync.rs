//! `sync_bdevs` — the device half of `sync(2)`.
//!
//! Two passes over every registered disk, in the reference's shape: the first
//! starts writeback of each disk's dirty device pages, the second waits for
//! what the first started and latches any error against the mapping so a later
//! `fsync` on that block-device fd still reports it. Splitting them is what
//! makes N devices cost one writeback latency instead of N.
//!
//! No barrier is issued here, and that is not an omission: the reference's
//! device pass is page-cache writeback only. Durability of a filesystem's own
//! device cache belongs to that filesystem's `sync_fs(wait=1)`, which already
//! issues the barrier; a raw block-device fd gets it from `fsync`, which is
//! writeback + `blkdev_issue_flush`.

use crate::registry;

/// `sync_bdevs(wait)` — one pass over the registered disks.
///
/// `wait == false` is the submit half; `wait == true` the wait half. A disk
/// with no resident device pages is skipped (there is nothing to write), as is
/// one with no opener (nothing has written it raw since its cache was last
/// reconciled). # C: O(N_disks x dirty)
pub fn sync_bdevs(wait: bool) {
    for disk in registry::snapshot() {
        if disk.mapping.nrpages() == 0 { continue; }
        if disk.opener_count() == 0 { continue; }
        if wait { let _ = disk.mapping.fdatawait_keep_errors(); }
        else { disk.mapping.fdatawrite(); }
    }
}
