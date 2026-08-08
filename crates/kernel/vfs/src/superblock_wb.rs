// Superblock dirty-inode writeback list (`s_inodes_wb`) per `16§2`.
//
// Linux keeps a dirty inode alive independent of any caller's reference: the
// per-bdi/`sb` writeback list (`__mark_inode_dirty` → `inode_io_list_move_locked`)
// holds a STRONG reference, and `iput_final` declines to free an inode while
// writeback still owes it. Without that, this crate's `Weak`-keyed icache frees
// an inode the instant its last external `Arc` drops, so a `mark_inode_dirty`
// after the drop lands on an already-evicted inode and `drop_caches`/`sync`
// lose it. [`SuperBlock::s_wb`] is that strong-pin list; this module drives it.

extern crate alloc;
use alloc::vec::Vec;

use crate::inode::{InodeRef, I_DIRTY_ALL};
use crate::superblock::SuperBlock;
use crate::types::Ino;

impl SuperBlock {
    /// Reconcile the writeback pin for `ino` against the inode's CURRENT
    /// `i_state` (call after any state mutation): a set `I_DIRTY_ALL` bit (a
    /// deferred lazy timestamp counts) inserts the
    /// STRONG `Arc` into `s_wb` (idempotent — an already-pinned dirty inode keeps
    /// its single pin), a fully-clean inode drops the pin so it becomes evictable.
    /// This is the `__mark_inode_dirty` add / writeback-done remove, expressed as
    /// one reconcile so every `i_set_state`/`mark_inode_dirty`/`clear_inode` path
    /// keeps `s_wb` exact. # C: O(log N_wb)
    pub(crate) fn wb_reconcile(&self, ino: Ino, inode: &InodeRef) {
        if inode.i_state() & I_DIRTY_ALL != 0 { self.wb_pin(ino, inode); } else { self.wb_forget(ino); }
    }

    /// Install the STRONG writeback pin for a now-dirty inode (idempotent). Kept
    /// apart from the unpin half so a caller that can only ever DIRTY an inode
    /// ([`crate::writeback::mark_inode_dirty`]) does not drag the B-tree REMOVE
    /// path — rebalance, merge, node free — into its static call graph. That
    /// path is the deepest thing reachable from `iput`, so the split is worth a
    /// named function. # C: O(log N_wb)
    pub(crate) fn wb_pin(&self, ino: Ino, inode: &InodeRef) {
        let mut wb = self.s_wb.lock();
        if !wb.contains_key(&ino) { wb.insert(ino, inode.clone()); }
    }

    /// Drop the writeback pin for `ino` unconditionally — the terminal
    /// `clear_inode`/`iput_final` path where the metadata is gone and no
    /// writeback will follow (Linux clears `I_DIRTY` then takes the inode off the
    /// writeback list). # C: O(log N_wb)
    pub(crate) fn wb_forget(&self, ino: Ino) { self.s_wb.lock().remove(&ino); }

    /// [`Self::wb_reconcile`] keyed off the inode's own `i_ino` — the form every
    /// writeback-path caller wants, since it holds the `Arc` already.
    /// # C: O(log N_wb)
    pub(crate) fn wb_reconcile_inode(&self, inode: &InodeRef) {
        self.wb_reconcile(inode.ino(), inode);
    }

    /// `s_inodes_wb` snapshot — every inode currently STRONG-pinned dirty (Linux
    /// the per-sb `b_dirty` + `b_dirty_time` lists), in `ino` order. The set
    /// `sync`/`fsync` walk to write back; an inode owing only a deferred
    /// timestamp is in it, which is what keeps a lazytime stamp alive until a
    /// forcing point pays it. # C: O(N_wb)
    pub fn wb_dirty_inodes(&self) -> Vec<InodeRef> {
        self.s_wb.lock().values().cloned().collect()
    }

    /// Count of dirty-pinned inodes (Linux per-bdi `b_dirty` length). # C: O(1)
    pub fn nr_dirty_inodes(&self) -> usize { self.s_wb.lock().len() }

    /// `invalidate_inodes` / per-sb `drop_caches`: sweep the inode cache dropping
    /// every CLEAN, UNREFERENCED slot so a `drop_caches`/remount reclaim shrinks
    /// the icache without touching live or dirty state. A slot is reclaimable
    /// only when its inode is UNUSED — in this `Weak`-keyed cache that is a slot
    /// whose `Weak::upgrade` already fails (Linux `i_count == 0`, no dentry alias
    /// pinning it). A DIRTY inode's `Weak` still upgrades because [`Self::s_wb`]
    /// holds the writeback `Arc`, so it reads as BUSY here and is RETAINED — the
    /// pin is exactly Linux skipping dirty/in-flight inodes (writeback still owns
    /// them). Dead alias `Weak`s are pruned from every surviving slot on the way
    /// past. Returns the count of slots dropped. # C: O(N_ino)
    pub fn drop_caches(&self) -> u32 {
        let mut dropped = 0u32;
        self.icache.lock().retain(|_, e| {
            e.aliases.retain(|w| w.upgrade().is_some());
            // Reclaimable = the inode's last `Arc` already dropped (Linux
            // `i_count == 0`). A dirty inode is pinned by `s_wb` so its `Weak`
            // upgrades → BUSY → retained; a dead `Weak` is clean and unused.
            if e.inode.upgrade().is_some() { true } else { dropped += 1; false }
        });
        dropped
    }
}
