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

use crate::inode::{InodeRef, I_DIRTY};
use crate::superblock::SuperBlock;
use crate::types::Ino;

impl SuperBlock {
    /// Reconcile the writeback pin for `ino` against the inode's CURRENT
    /// `i_state` (call after any state mutation): a set `I_DIRTY` bit inserts the
    /// STRONG `Arc` into `s_wb` (idempotent — an already-pinned dirty inode keeps
    /// its single pin), a fully-clean inode drops the pin so it becomes evictable.
    /// This is the `__mark_inode_dirty` add / writeback-done remove, expressed as
    /// one reconcile so every `i_set_state`/`mark_inode_dirty`/`clear_inode` path
    /// keeps `s_wb` exact. # C: O(log N_wb)
    pub(crate) fn wb_reconcile(&self, ino: Ino, inode: &InodeRef) {
        if inode.i_state() & I_DIRTY != 0 {
            self.s_wb.lock().entry(ino).or_insert_with(|| inode.clone());
        } else {
            self.s_wb.lock().remove(&ino);
        }
    }

    /// Drop the writeback pin for `ino` unconditionally — the terminal
    /// `clear_inode`/`iput_final` path where the metadata is gone and no
    /// writeback will follow (Linux clears `I_DIRTY` then takes the inode off the
    /// writeback list). # C: O(log N_wb)
    pub(crate) fn wb_forget(&self, ino: Ino) { self.s_wb.lock().remove(&ino); }

    /// `s_inodes_wb` snapshot — every inode currently STRONG-pinned dirty (Linux
    /// the per-sb writeback list), in `ino` order. The set `sync`/`fsync` walk to
    /// write back. # C: O(N_wb)
    pub fn wb_dirty_inodes(&self) -> Vec<InodeRef> {
        self.s_wb.lock().values().cloned().collect()
    }

    /// Count of dirty-pinned inodes (Linux per-bdi `b_dirty` length). # C: O(1)
    pub fn nr_dirty_inodes(&self) -> usize { self.s_wb.lock().len() }

    /// `sync_inodes_sb` writeback completion (Linux fs/fs-writeback.c): the wait
    /// pass of [`SuperBlock::sync_filesystem`] has flushed the backend, so every
    /// dirty-pinned inode is now clean — clear its `I_DIRTY` bits and drop the
    /// writeback pin, leaving a now-clean unreferenced inode evictable by the next
    /// `drop_caches`. Snapshots the list first so the per-inode unpin does not
    /// mutate the map under its own iterator. # C: O(N_wb)
    pub(crate) fn wb_writeback(&self) {
        let dirty: Vec<(Ino, InodeRef)> = self.s_wb.lock().iter().map(|(k, v)| (*k, v.clone())).collect();
        for (ino, inode) in dirty {
            inode.set_state(0, I_DIRTY); // writeback done — inode is clean
            self.s_wb.lock().remove(&ino);
        }
    }

    /// `invalidate_inodes` / per-sb `drop_caches` (Linux fs/inode.c
    /// `invalidate_inodes`, fs/drop_caches.c): sweep the inode cache dropping
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
