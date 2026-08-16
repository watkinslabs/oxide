//! A mounted volume: everything below this file, driven against a real medium.
//!
//! The medium is a trait rather than a block device, so a whole volume —
//! superblock, checkpoint, both tables, node blocks, directories and file
//! bytes — is exercised end to end against an image in memory. Every layer
//! under this one is tested alone; this is where they are tested TOGETHER,
//! which is the only place a mistake between them shows.
//!
//! Module manifest:
//! - `mount`:  reading the superblock and checkpoint, and deciding access.
//! - `nodes`:  a node id into a node block, and an inode out of one.
//! - `map`:    a file's block index into a block address.
//! - `io`:     a file's bytes, inline or otherwise.
//! - `dir`:    lookup and listing, inline or otherwise.
//! - `xattrs`: the attribute region, assembled from its two halves.
//! - `space`:  what `statfs` reports.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::checkpoint::Checkpoint;
use crate::features::Access;
use crate::node::Inode;
use crate::opts::Options;
use crate::sb::SuperBlock;
use crate::summary::{NatJournal, SitJournal};
use crate::uapi::BLKSIZE;

pub mod mount;
pub mod nodes;
pub mod map;
pub mod io;
pub mod dir;
pub mod xattrs;
pub mod space;

pub use dir::DirEntry;
pub use nodes::NodeRef;

/// A mounted volume.
pub struct Volume<S: SectorSource> {
    pub(crate) source: S,
    pub(crate) sb: SuperBlock,
    pub(crate) cp: Checkpoint,
    /// The checkpoint's head block and its payload blocks, joined, because
    /// the version bitmaps run from one into the next.
    pub(crate) cp_raw: Vec<u8>,
    pub(crate) nat_bitmap: Vec<u8>,
    pub(crate) sit_bitmap: Vec<u8>,
    /// The recently-changed table entries the last checkpoint parked in the
    /// current segments. These OVERRIDE the tables; see `nat`.
    pub(crate) nat_journal: NatJournal,
    pub(crate) sit_journal: SitJournal,
    /// The per-volume seed every inode checksum starts from.
    pub(crate) inode_seed: u32,
    pub(crate) opts: Options,
    pub(crate) access: Access,
    pub(crate) writable: bool,
}

impl<S: SectorSource> Volume<S> {
    /// The volume's superblock. # C: O(1)
    pub fn super_block(&self) -> &SuperBlock { &self.sb }

    /// The checkpoint this mount is reading through. # C: O(1)
    pub fn checkpoint(&self) -> &Checkpoint { &self.cp }

    /// The checkpoint's own bytes, head block and payload joined. Kept because
    /// the two version bitmaps run from one block into the next, so neither
    /// can be sliced out of the head alone. # C: O(1)
    pub fn checkpoint_bytes(&self) -> &[u8] { &self.cp_raw }

    /// This mount's option set. # C: O(1)
    pub fn options(&self) -> &Options { &self.opts }

    /// Whether this mount may write. # C: O(1)
    pub fn writable(&self) -> bool { self.writable }

    /// What the volume's own features permit, regardless of what the mount
    /// asked for. # C: O(1)
    pub fn access(&self) -> Access { self.access }

    /// The inode number of the root directory. # C: O(1)
    pub fn root_ino(&self) -> u32 { self.sb.root_ino }

    /// Read one block by its address.
    ///
    /// Addresses are in blocks and the source is addressed in blocks, so the
    /// two units are the same here by construction — which is why the source
    /// is created at the volume's block size rather than at a sector size.
    /// # C: O(BLKSIZE)
    pub fn read_block(&self, addr: u32) -> Result<Vec<u8>, Errno> {
        if u64::from(addr) >= self.sb.max_blkaddr() { return Err(Errno::Eio); }
        let mut buf = vec![0u8; BLKSIZE];
        self.source.read_sectors(u64::from(addr), &mut buf)?;
        Ok(buf)
    }

    /// Read one block that must lie in the MAIN area.
    ///
    /// Everything a file or a node points at lives there. An address outside
    /// it names metadata, and following one would read a checkpoint or a table
    /// block as if it were data.
    /// # C: O(BLKSIZE)
    pub fn read_main_block(&self, addr: u32) -> Result<Vec<u8>, Errno> {
        if !self.sb.valid_main_blkaddr(addr) { return Err(Errno::Eio); }
        self.read_block(addr)
    }

    /// The root directory's inode. # C: O(1 block)
    pub fn root(&self) -> Result<Inode, Errno> { self.read_inode(self.sb.root_ino) }
}

#[cfg(test)]
#[path = "tests/volume.rs"]
mod tests;
