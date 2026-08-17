//! The half of an inode's death that happens above the volume.
//!
//! A removal parks an inode and stops. It cannot do more, because it cannot see
//! who has the file open — that is the layer above's cached inode and its
//! references. So the two halves are split: the volume records the debt on the
//! orphan list, and this file makes the cached inode agree, so the keep-or-evict
//! decision reaches the eviction that pays the debt.
//!
//! Both directions of getting this wrong lose something real:
//!   - the cached count left too high: the decision keeps the inode, no
//!     eviction ever runs, and the file's blocks stay charged for the life of
//!     the mount even though nothing can reach them.
//!   - nothing holding the inode and no eviction forced: the same leak, because
//!     the cache holds only a weak reference, so there is no reference left to
//!     drop and nothing will ever ask.

use alloc::sync::Arc;

use vfs::KResult;

use crate::volume::Removed;

use super::{errno_to_vfs, F2fs};

impl F2fs {
    /// Finish what a removal started for the inode it unnamed.
    ///
    /// Ordered as it is for a reason: the stored count is pushed into the cached
    /// inode FIRST, so that if a holder exists its eventual reference drop
    /// reaches the eviction, and only a parked inode nothing holds is evicted
    /// here and now.
    /// # C: O(log N_ino), plus the inode's blocks when it is evicted here
    pub(crate) fn after_remove(self: &Arc<Self>, out: Removed) -> KResult<()> {
        let held = self.sync_incore_nlink(out);
        // A file that still has a name is not going anywhere; the count was the
        // only thing owed to it.
        if !out.parked() { return Ok(()); }
        if held { return Ok(()); }
        // Nothing holds it, so nothing can ever ask on its behalf. Freeing it
        // now is what keeps every unlink of an unopened file from leaking its
        // blocks until the volume is unmounted.
        self.volume.lock().evict_inode(out.ino).map_err(errno_to_vfs)
    }

    /// Push the stored link count into the cached inode, and report whether
    /// anything still HOLDS that inode.
    ///
    /// The stored value is the truth; a stale cached one would leave the
    /// keep-or-evict decision believing a file with no names is still linked.
    ///
    /// "Holds it" is a strong count above one: the one reference is the handle
    /// the cache lookup just upgraded, so anything beyond it is a live owner —
    /// an open description, a dentry alias — whose own drop will reach the
    /// eviction. The cache keeps only a weak reference, so at exactly one there
    /// is nobody left to drop and the caller has to act.
    /// # C: O(log N_ino)
    fn sync_incore_nlink(&self, out: Removed) -> bool {
        let Some(sb) = self.sb.lock().upgrade() else { return false };
        let Some(victim) = sb.ilookup(u64::from(out.ino)) else { return false };
        victim.set_nlink(out.links);
        Arc::strong_count(&victim) > 1
    }
}
