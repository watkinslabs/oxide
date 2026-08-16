//! `/sys/fs/f2fs/<dev>/stat/` — the two status words, and what is outstanding.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::flags::CP_FSCK_FLAG;
use crate::fsattr::Attr;
use crate::mount::F2fs;

use super::volume::{hex, num, Vol};

/// Bit positions of the in-memory status word `stat/sb_status` reports.
///
/// Each is a condition a mount is in RIGHT NOW, as against `cp_status`, which
/// is the flag word the checkpoint on the medium carries. The positions are
/// the ABI: a reader decodes the word by bit number, so they are named rather
/// than written into the shift.
mod sbi {
    /// Something is waiting for a checkpoint.
    pub const IS_DIRTY: u32 = 0;
    /// The volume needs `fsck` — this mount saw the checkpoint say so.
    pub const NEED_FSCK: u32 = 2;
    /// A recovery replay is in progress.
    pub const POR_DOING: u32 = 3;
    /// Checkpointing is off for this mount.
    pub const CP_DISABLED: u32 = 8;
    /// The mount may write.
    pub const IS_WRITABLE: u32 = 15;
}

/// The in-memory status word.
///
/// Only conditions this build actually tracks can set a bit. A bit left clear
/// for a condition nothing detects reads the same as a condition that is not
/// happening — which is the honest report available, and is why the set of
/// bits that can ever be raised is written down here rather than implied.
/// # C: O(1)
pub fn status_word(dirty: bool, recovering: bool, writable: bool, cp_disabled: bool,
                   cp_flags: u32) -> u64 {
    let mut w = 0u64;
    if dirty { w |= 1 << sbi::IS_DIRTY; }
    if cp_flags & CP_FSCK_FLAG != 0 { w |= 1 << sbi::NEED_FSCK; }
    if recovering { w |= 1 << sbi::POR_DOING; }
    if cp_disabled { w |= 1 << sbi::CP_DISABLED; }
    if writable { w |= 1 << sbi::IS_WRITABLE; }
    w
}

/// # C: O(1)
fn sb_status(v: &mut Vol) -> Result<u64, Errno> {
    Ok(status_word(v.is_dirty(), v.recovering, v.writable(),
                   v.options().checkpoint_disabled, v.checkpoint().flags))
}

/// Blocks released since the last checkpoint that the device has not been
/// told about yet. # C: O(1)
fn undiscard_blks(v: &mut Vol) -> Result<u64, Errno> {
    Ok(v.pending_discard.len() as u64)
}

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
