//! `/sys/fs/f2fs/<dev>/stat/` — the two status words, and what is outstanding.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::fsattr::Attr;
use crate::mount::F2fs;

use super::volume::{hex, num, Vol};

/// The in-memory status word: every condition this mount is in right now, as
/// against `cp_status`, which is the flag word the checkpoint on the medium
/// carries.
///
/// Composed in ONE place, by the volume, and read here. A second word
/// assembled from a handful of the volume's fields is a second answer to the
/// same question, and the two drift the moment a bit is added to either.
/// # C: O(1)
fn sb_status(v: &mut Vol) -> Result<u64, Errno> { Ok(v.sb_status()) }

/// Blocks the discard machinery is holding and has not announced.
///
/// The discard control's own count, not the volume's list of addresses released
/// since the last checkpoint: those are not announceable until the checkpoint
/// lands, so counting them here would report as outstanding blocks the device
/// may never be told about.
/// # C: O(runs waiting)
fn undiscard_blks(v: &mut Vol) -> Result<u64, Errno> { Ok(v.discard_blocks_waiting()) }

/// The `stat/` attributes.
///
/// Upstream also publishes `issued_discard` and `queued_discard`, which count
/// requests the discard thread has handed to the device and requests in
/// flight. This build announces discards inline from the checkpoint path and
/// has no such thread, so there is nothing that has ever been in either state
/// and no counter to report — an entry reading a permanent zero would say the
/// thread exists and is idle.
/// # C: O(1)
pub(crate) fn attrs(fs: &Arc<F2fs>, dev: &str) -> Vec<Attr> {
    let dir = alloc::format!("{dev}/stat");
    alloc::vec![
        hex(fs, &dir, "sb_status", sb_status),
        hex(fs, &dir, "cp_status", |v| Ok(u64::from(v.checkpoint().flags))),
        num(fs, &dir, "undiscard_blks", undiscard_blks),
    ]
}
