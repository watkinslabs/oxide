//! What is thrown away when a replay fails part way through.
//!
//! A replay rewrites nodes, may create an inode and may add a directory entry,
//! and NONE of it reaches the medium while it runs: every node it changes goes
//! into the node mapping, every page into the file mapping, and the checkpoint
//! that closes recovery is what places them. That is what makes a failure
//! recoverable at all — and it is also what makes a failure dangerous, because
//! the half-built state is sitting in two mappings that anything else may
//! write back.
//!
//! Two things would write it. This mount's own next checkpoint, if the caller
//! carried on; and the MACHINE's flusher, which reaches those pages from
//! outside this filesystem's lock and does not know a repair failed. A page
//! written by either describes a volume state that was never reached: an inode
//! whose blocks were half re-pointed, a directory entry naming an inode the
//! replay never finished creating. The next mount would then replay from a
//! chain that no longer matches its own tables.
//!
//! So the mappings are emptied, which is what the reference does with the same
//! two mappings and for the same reason. Emptying is safe precisely because
//! nothing here was ever placed: the medium still holds the state the crashed
//! mount left, chain included, and the next mount reads exactly what this one
//! read.
//!
//! The in-memory tables go with them. The segment table is DROPPED rather than
//! repaired, so the next reader loads it from the medium again — a table
//! carrying the live-marks the replay made for blocks it then failed to use
//! would keep those blocks out of the allocator's reach for the life of the
//! mount, and would disagree with the medium about how many are free.

use sectors::SectorSource;

use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// Discard everything a failed replay built.
    ///
    /// Returns nothing and cannot fail: it is called on the way out of a
    /// failure, and a second error here would replace the diagnosis the caller
    /// is about to report with a less useful one.
    /// # C: O(pages held)
    pub(crate) fn drop_failed_replay(&mut self) {
        // The nodes first: they are the only copy of every change the replay
        // made, and the only pages here that are dirty.
        self.node_cache.forget_all();
        for ino in self.data_cache.dirty_inodes() { self.data_cache.forget_inode(ino); }
        // Clean pages, so this buys correctness rather than accounting: a
        // metadata block the replay rewrote and this mapping still held would
        // answer a later read with the pre-replay copy.
        self.meta_cache.invalidate_range(0, u32::MAX);
        // The table changes, which are not on the medium either. `nat_dirty`
        // beats the journal and the table on every read, so an entry left here
        // would point a node id at a block the replay chose and never wrote.
        self.nat_dirty.clear();
        self.sit_dirty.clear();
        self.sit = None;
        // And nothing is owed a checkpoint any more. A checkpoint written from
        // here would publish the tables the two lines above just abandoned.
        self.dirty = false;
    }
}

#[cfg(test)]
#[path = "../../tests/recover/cleanup.rs"]
mod tests;
