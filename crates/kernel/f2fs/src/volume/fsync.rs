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

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::mode;
use crate::opts::FsyncMode;

use super::Volume;

pub mod reason;
pub mod advise;
pub mod nodes;

pub use reason::{need_checkpoint, CpReason, SyncState};

impl<S: SectorSource> Volume<S> {
    /// Whether the node `nid` names reached the last checkpoint.
    ///
    /// A node this mount has written is only in memory: the table on the
    /// medium still names the block it replaced, so nothing a reader could do
    /// after a crash would find it.
    /// # C: O(1)
    pub(crate) fn node_is_checkpointed(&self, nid: u32) -> bool {
        !self.nat_dirty.contains_key(&nid)
    }

    /// Everything the checkpoint decision reads, for one file.
    /// # C: O(2 blocks)
    pub(crate) fn sync_state(&self, ino: u32) -> Result<SyncState, Errno> {
        let inode = self.read_inode(ino)?;
        let pino = inode.pino;
        let parent_xattr_written = match self.read_inode(pino) {
            Ok(p) => p.xattr_nid != 0 && !self.node_is_checkpointed(p.xattr_nid),
            Err(_) => false,
        };
        Ok(SyncState {
            regular: mode::file_type(inode.mode) == vfs::FileType::Regular,
            compressed: inode.compressed(),
            links: inode.links,
            pino_ok: !advise::wrong_pino(inode.advise),
            space_for_roll_forward: self.space_for_roll_forward(),
            parent_checkpointed: self.node_is_checkpointed(pino),
            active_logs: self.opts.active_logs,
            strict: self.opts.fsync_mode == FsyncMode::Strict,
            need_dentry_mark: !self.node_is_checkpointed(ino),
            parent_dir_written: !self.node_is_checkpointed(pino),
            parent_xattr_written,
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
        if !self.writable { return Ok(CpReason::None); }
        let state = self.sync_state(ino)?;
        let reason = need_checkpoint(&state);
        if reason.needed() {
            self.commit()?;
            return Ok(reason);
        }
        self.write_fsync_chain(ino, state.need_dentry_mark)?;
        Ok(CpReason::None)
    }
}

#[cfg(test)]
#[path = "../tests/fsync.rs"]
mod tests;
