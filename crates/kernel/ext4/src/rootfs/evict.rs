// Inode eviction — the `iput_final` → `ext4_evict_inode` half of the unlink
// contract (`fs/ext4/inode.c` `ext4_evict_inode`, `fs/inode.c` `iput`).
//
// `Mount::unlink` removes the NAME and, on the last link, records the inode on
// the on-disk orphan list. Nothing is freed there. This module owns the other
// end: deciding whether a still-referenced inode must wait for its last
// reference, and performing the truncate-and-free when that reference goes.
//
// One implementation of the free (`RootfsState::evict_orphan`), several
// triggers — exactly as Linux: `iput_final` (fd/dentry drop),
// `evict_inodes` at umount (`Ext4Mount::drop`), and `orphan_cleanup` at mount
// after a crash.

use alloc::sync::Arc;

use crate::ialloc::UnlinkOutcome;
use super::inode::ext4_wrap_ino;
use super::RootfsState;

impl RootfsState {
    /// `ext4_unlink`'s tail plus `vfs_unlink`'s: publish the orphan, sync the
    /// in-core `i_nlink` with what went to disk, and decide who frees.
    ///
    /// Returns `Ok(())` in both cases. When a counted holder exists (an open
    /// file description or a dentry alias, i.e. `i_count > 0`) the free is
    /// DEFERRED to [`Self::evict_orphan`] via `s_op->evict_inode` — that is
    /// what keeps an unlinked-but-open file readable and writable through its
    /// fd. With no in-core inode at all nothing will ever `iput`, so this call
    /// is the last reference and frees immediately.
    /// # C: O(1), or the eviction cost when it frees here
    pub fn after_unlink(self: &Arc<Self>, out: UnlinkOutcome) -> Result<(), vfs::VfsError> {
        if !out.orphaned() { self.sync_incore_nlink(out); return Ok(()); }
        self.orphan_insert(out.ino);
        if self.sync_incore_nlink(out) { return Ok(()); }
        self.evict_orphan(out.ino)
    }

    /// Push the on-disk `i_links_count` into the cached inode and report
    /// whether anyone still HOLDS it. The on-disk value is the truth: a stale
    /// in-core count would leave `drop_inode` believing the file is still
    /// linked and the blocks would never come back.
    ///
    /// "Holds it" is `Arc::strong_count > 1` — one strong reference is the
    /// handle `ilookup` just upgraded, so anything above that is a live owner
    /// (an open `File`, a dentry alias) whose `iput` will reach
    /// `evict_inode`. The icache itself keeps only a `Weak`, so with no other
    /// strong reference NOTHING can ever `iput` this inode and the caller must
    /// evict it now or the space leaks until umount.
    /// # C: O(log N_ino)
    fn sync_incore_nlink(&self, out: UnlinkOutcome) -> bool {
        let sb = match self.i_sb() { Some(s) => s, None => return false };
        let victim = match sb.ilookup(ext4_wrap_ino(out.ino)) { Some(v) => v, None => return false };
        victim.set_nlink(out.links as u32);
        Arc::strong_count(&victim) > 1
    }

    /// `ext4_evict_inode` for an inode whose links are gone: truncate every
    /// data block, drop the external xattr block, splice it off the orphan
    /// list, stamp `i_dtime`, free the inode slot, release its quota charge,
    /// and drop its page cache. A no-op if the inode was re-linked in the
    /// meantime (`linkat` on an O_TMPFILE, `orphan_del` already ran).
    /// # C: O(N_extents) block frees + 1 inode free
    pub fn evict_orphan(&self, ino: u32) -> Result<(), vfs::VfsError> {
        let r = self.free_orphan_inode(ino);
        self.orphan_remove(ino);
        r
    }
}
