//! Making ONE file durable without paying for a checkpoint.
//!
//! A checkpoint rewrites both tables and a whole pack; doing that per `fsync`
//! turns a database's every commit into a filesystem-wide flush. The cheaper
//! promise is a chain: write the file's own node blocks into the log with a
//! mark and a forward pointer, and leave the tables alone. Nothing on the
//! medium points at those blocks — the node table still names the previous
//! generation — so a mount that finds them must go looking, which is what
//! `recover` does.
//!
//! The promise is only honest while replay can reconstruct the file from the
//! chain alone. `reason` holds the states in which it cannot, and each of them
//! sends the call down the checkpoint path instead. Getting that ladder wrong
//! is silent: the fsync returns, the caller believes the data is safe, and the
//! next crash proves otherwise.
//!
//! Module manifest:
//! - `reason`: whether a checkpoint is unavoidable, as a pure decision.
//! - `advise`: the inode hint bits that decision and replay both read.
//! - `nodes`:  which node blocks go into the chain, and how they are stamped.
//! - `dirty`:  what changed since the checkpoint, and on which side.
//! - `fsynced`: whether the chain already states this file's name.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::devices::barrier;
use crate::mode;
use crate::opts::FsyncMode;

use super::Volume;

pub mod reason;
pub mod advise;
pub mod nodes;
pub mod dirty;
pub mod fsynced;

pub use dirty::Dirty;
pub use reason::{need_checkpoint, CpReason, SyncState};

impl<S: SectorSource> Volume<S> {
    /// Everything the checkpoint decision reads, for one file.
    /// # C: O(chain length) blocks for a file the checkpoint never saw
    pub(crate) fn sync_state(&self, ino: u32) -> Result<SyncState, Errno> {
        use crate::checkpoint::InoKind;
        let inode = self.read_inode(ino)?;
        let pino = inode.pino;
        Ok(SyncState {
            regular: mode::file_type(inode.mode) == vfs::FileType::Regular,
            compressed: inode.compressed(),
            links: inode.links,
            sb_need_cp: self.sbi.need_cp(),
            pino_ok: !advise::wrong_pino(inode.advise),
            space_for_roll_forward: self.space_for_roll_forward(),
            parent_checkpointed: self.node_is_checkpointed(pino),
            fastboot: self.opts.fastboot,
            active_logs: self.opts.active_logs,
            strict: self.opts.fsync_mode == FsyncMode::Strict,
            need_dentry_mark: self.need_dentry_mark(ino)?,
            parent_in_trans_dir: self.ino_lists.exists(InoKind::TransDir, pino),
            parent_in_xattr_dir: self.ino_lists.exists(InoKind::XattrDir, pino),
        })
    }

    /// Whether the volume has room for the blocks a replay would write.
    ///
    /// Replay writes as it goes, so a volume with no room left cannot be
    /// recovered from a chain at all, and promising durability through one
    /// would be a promise the next mount cannot keep.
    /// # C: O(1)
    pub(crate) fn space_for_roll_forward(&self) -> bool {
        self.valid_block_count < self.cp.user_block_count
    }

    /// Make `ino` durable, and report which path it took.
    ///
    /// A mount that may not write reports success without writing: there is
    /// nothing it could have failed to persist.
    /// # C: O(nodes the file has) blocks, or O(a checkpoint)
    pub fn fsync(&mut self, ino: u32) -> Result<CpReason, Errno> {
        self.sync_file(ino, false, true)
    }

    /// Prepare the one-file durability decision for the mount adapter. A
    /// checkpoint reason is returned to the adapter so it can hand the write
    /// to the mount's merge thread after releasing this volume lock.
    pub(crate) fn fsync_for_mount(&mut self, ino: u32, datasync: bool)
        -> Result<CpReason, Errno>
    {
        self.deferred_flush = Some((ino, 0));
        self.sync_file(ino, datasync, false)
    }

    /// Make `ino`'s CONTENTS durable, and report which path it took.
    ///
    /// The difference from [`Volume::fsync`] is one state: a file whose only
    /// change since the checkpoint is its times or its mode. That is durable
    /// enough already for what this call promises, so it writes nothing —
    /// which is the whole point of the call, since every read and every write
    /// moves a timestamp.
    /// # C: O(nodes the file has) blocks, or O(a checkpoint), or none
    pub fn fdatasync(&mut self, ino: u32) -> Result<CpReason, Errno> {
        self.sync_file(ino, true, true)
    }

    /// The path both calls take, parted only by what each promised.
    /// # C: O(nodes the file has) blocks, or O(a checkpoint), or none
    fn sync_file(&mut self, ino: u32, datasync: bool, commit_checkpoint: bool)
        -> Result<CpReason, Errno>
    {
        if !self.writable { return Ok(CpReason::None); }
        // The DATA first, always, and before the decision below reads what
        // changed. The chain names node blocks and each node names the
        // addresses of its file's data; writing the chain over pages that have
        // not been placed would leave it naming reservations, and a replay
        // would recover a file of holes where the caller was promised bytes.
        //
        // A sync of the DATA alone, or of a short tail, asks for those pages to
        // be rewritten where they lie: the caller wants the bytes durable and
        // is paying for every node block an out-of-place write would move
        // (`crate::place::ipu`). Armed for the length of this flush only — it
        // is a statement about the call, not about the file.
        let wants_ipu = crate::place::ipu::fsync_wants_ipu(
            datasync, self.dirty_data_pages(ino), self.place.min_fsync_blocks);
        self.need_ipu = if wants_ipu { Some(ino) } else { None };
        let flushed = self.flush_data_pages(ino);
        self.need_ipu = None;
        flushed?;
        // Nothing to make durable is answered before the ladder, not inside
        // it: a checkpoint written for a file that has not changed makes the
        // whole volume pay for a call that had nothing to do.
        //
        // "Changed" is read off the file's recorded shape, and a page rewritten
        // IN PLACE changes none of it — same block, same slot, same count — so
        // such a file compares identical to its checkpointed generation while
        // its new bytes sit in the device's cache. That is the one state in
        // which there is nothing to WRITE and a barrier is nonetheless owed,
        // and it is the reference's own third answer here.
        let dirty = self.inode_dirty(ino)?.needs_sync(datasync);
        match barrier::sync_work(dirty, self.owes_inplace_barrier(ino)) {
            barrier::SyncWork::Nothing => return Ok(CpReason::None),
            barrier::SyncWork::BarrierOnly => {
                self.fsync_barrier(ino, self.is_atomic_file(ino))?;
                return Ok(CpReason::None);
            }
            barrier::SyncWork::Full => {}
        }
        let state = self.sync_state(ino)?;
        let reason = need_checkpoint(&state);
        if reason.needed() {
            // No barrier on this leg, and that is not an omission: a checkpoint
            // ends in a commit block written under its own durability promise,
            // so everything this call was to make durable has already been
            // fenced. Asking again would cost a second barrier for one
            // guarantee.
            if commit_checkpoint { self.commit()?; }
            return Ok(reason);
        }
        self.write_fsync_chain(ino, state.need_dentry_mark)?;
        // The recovery info is now on the medium, so there is no longer written
        // data this file needs a chain for — the reference drops the same record
        // at the same point, once the chain is written and before the barrier.
        self.ino_lists.remove(crate::checkpoint::InoKind::Append, ino);
        // The recovery info is now on the medium, so there is no longer written
        // data this file needs a chain for — the reference drops the same record
        // at the same point, once the chain is written and before the barrier.
        // And THEN the barrier, which is what makes the call's promise true. The
        // chain is a run of node blocks a later mount goes looking for; a device
        // with a volatile cache has acknowledged them without putting them on
        // the medium and is free to reorder them, so returning here without
        // fencing would report durability for bytes a power cut still loses.
        // Whether one is owed at all is the mount's decision — see
        // `devices::barrier`.
        self.fsync_barrier(ino, self.is_atomic_file(ino))?;
        Ok(CpReason::None)
    }
}

#[cfg(test)]
#[path = "../tests/fsync.rs"]
mod tests;
