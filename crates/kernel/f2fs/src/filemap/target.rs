//! Where a dirty data page goes when something OUTSIDE this filesystem
//! decides it must be written.
//!
//! Two directions reach a dirty page and they are not symmetric.
//!
//! - This filesystem's own flush points — `fsync`, a checkpoint, a truncate,
//!   the cleaner — are already holding the volume, which is the state placing
//!   a page needs. They hand the batch straight to the volume and never come
//!   through here; going through here would have them wait on themselves.
//! - The machine's flusher and page reclaim arrive holding nothing. They have
//!   only the mapping, so the mapping has to carry a way back to the mount:
//!   that is this.
//!
//! The way back is WEAK. A mount that has gone away must not be kept alive by
//! a page still on a reclaim list, and a page whose mount is gone has nowhere
//! to be put — which is reported as a failed write, so the page stays dirty
//! rather than being dropped with the caller believing it landed.

use alloc::sync::{Arc, Weak};

use block::pagecache::{PageOut, Writeback};
use block::types::{BlockError, InodeId, KResult};

use sync::{Spinlock, Superblock};

/// The mount a mapping's pages belong to, as much of it as writeback needs.
///
/// A trait rather than the mount itself so this file does not have to name the
/// VFS-facing type: the mapping is built while the volume is being mounted,
/// before anything that could implement this exists.
pub trait DataHost: Send + Sync {
    /// Put this batch of one inode's pages on the medium, choosing an address
    /// for each. One slot of `results` per page, prefilled with a failure.
    /// # Ctx: process # Sleeps: y # C: O(pages)
    fn writeback_data(&self, ino: u32, pages: &[PageOut<'_>], results: &mut [KResult<()>]);
    /// Barrier every device the volume spans. # C: O(devices)
    fn sync_data_medium(&self) -> KResult<()>;
}

/// The writeback target every mapping of one mount shares.
///
/// One instance per mount rather than one per inode: the batch a target is
/// given names its inode, so nothing about the work is per-inode, and an
/// instance per file would be a mount-lifetime allocation per file ever
/// written.
pub struct Target {
    host: Spinlock<Option<Weak<dyn DataHost>>, Superblock>,
}

impl Target {
    /// # C: O(1)
    pub fn new() -> Arc<Self> { Arc::new(Self { host: Spinlock::new(None) }) }

    /// Name the mount these pages belong to.
    ///
    /// Separate from construction because the mapping exists before the mount
    /// does — the volume builds it on the way up, and only once the volume is
    /// inside the filesystem is there anything to point at.
    /// # C: O(1)
    pub fn set_host(&self, host: Weak<dyn DataHost>) { *self.host.lock() = Some(host); }

    /// # C: O(1)
    fn host(&self) -> Option<Arc<dyn DataHost>> { self.host.lock().as_ref()?.upgrade() }
}

impl Writeback for Target {
    /// # Ctx: process # Sleeps: y # C: O(pages)
    fn writepages(&self, ino: InodeId, pages: &[PageOut<'_>], results: &mut [KResult<()>]) {
        // No mount to place them in. The slots arrive prefilled with a
        // failure, so leaving them is what re-dirties every page — the bytes
        // stay where they are and this filesystem's own flush point still has
        // them to write.
        let Some(host) = self.host() else { return; };
        let Ok(ino) = u32::try_from(ino.0) else { return; };
        host.writeback_data(ino, pages, results);
    }

    /// # C: O(devices)
    fn sync_medium(&self) -> KResult<()> {
        match self.host() { Some(h) => h.sync_data_medium(), None => Err(BlockError::Eio) }
    }
}
