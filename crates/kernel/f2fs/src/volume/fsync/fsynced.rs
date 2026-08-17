//! Whether an `fsync` has ALREADY put a file's inode block into the chain
//! since the last checkpoint.
//!
//! The dentry mark is the crashed mount's statement that a file's directory
//! entry may not survive, so replay should re-add it from the block carrying
//! the mark. It belongs on the FIRST marked inode block of a file and on no
//! later one: once a block in the chain states the name, the entry is already
//! recoverable, and marking every subsequent one both repeats work replay has
//! done and — under a strict mount — forces whole checkpoints that the file's
//! state does not need.
//!
//! The state is read from the chain rather than remembered. The chain IS the
//! record of what this generation has written, so walking it cannot disagree
//! with what is on the medium, which a remembered bit eventually would. The
//! cost is the walk: it is paid only for a file the last checkpoint never saw,
//! which is the only case in which the answer can be anything but false.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::*;
use crate::volume::curseg::{self, Kind};
use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
    /// Where a walk of everything this generation has written begins.
    ///
    /// Read from the CHECKPOINT, not from the open log: the log has advanced
    /// past every block written since, so starting there finds the tail and
    /// concludes that nothing was ever written.
    /// # C: O(1)
    pub(crate) fn generation_chain_start(&self) -> u32 {
        let log = curseg::log_for(Kind::FileNode, self.opts.active_logs);
        let (node, i) = curseg::cp_slot(log);
        let (segno, blkoff) = if node {
            (self.cp.cur_node_segno[i], self.cp.cur_node_blkoff[i])
        } else {
            (self.cp.cur_data_segno[i], self.cp.cur_data_blkoff[i])
        };
        self.sb.main_blkaddr + segno * BLKS_PER_SEG + u32::from(blkoff)
    }

    /// Whether a marked inode block for `ino` is already in this generation's
    /// chain. # C: O(chain length) blocks
    pub(crate) fn inode_is_fsynced(&self, ino: u32) -> Result<bool, Errno> {
        let mut found = false;
        self.walk_chain(self.generation_chain_start(), &mut |f| {
            if f.is_inode && f.ino == ino { found = true; }
            !found
        })?;
        Ok(found)
    }

    /// Whether the next chain write for `ino` must carry the dentry mark.
    ///
    /// Both halves matter and neither alone is enough. A file the checkpoint
    /// already holds has a name on the medium and needs nothing; a file whose
    /// name is already stated by an earlier block of this chain needs nothing
    /// either.
    /// # C: O(chain length) blocks, none for a checkpointed file
    pub(crate) fn need_dentry_mark(&self, ino: u32) -> Result<bool, Errno> {
        if self.node_is_checkpointed(ino) { return Ok(false); }
        Ok(!self.inode_is_fsynced(ino)?)
    }
}

#[cfg(test)]
#[path = "../../tests/fsync/fsynced.rs"]
mod tests;
