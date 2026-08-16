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
//! - `curseg`: the six open logs, and which one a write appends to.
//! - `segmap`: which blocks are live and which segments are free.
//! - `write`:  allocating a block and putting a node or a page in it.
//! - `dnode`:  reaching — and creating — the node holding a block's address.
//! - `trim`:   freeing the nodes a shortened file no longer needs.
//! - `commit`: writing a checkpoint to the other pack.
//! - `nodes`:  a node id into a node block, and an inode out of one.
//! - `map`:    a file's block index into a block address.
//! - `io`:     a file's bytes, inline or otherwise.
//! - `dir`:    lookup and listing, inline or otherwise.
//! - `xattrs`: the attribute region, assembled from its two halves.
//! - `fileops`: writing a file's bytes, and shortening one.
//! - `dirwrite`: adding and removing directory entries.
//! - `namei`:  creating, removing and renaming names.
//! - `xattr_write`: setting and removing attributes.
//! - `quotas`:  charging allocations to the identities that own them.
//! - `verify`:  attesting a verity file's data against its hash tree.
//! - `verity_on`: building that tree and sealing the file behind it.
//! - `discard`: telling the device which blocks the volume no longer needs.
//! - `gc`:      cleaning a segment so its space comes back.
//! - `orphan`:  inodes unlinked while still open.
//! - `recover`: replaying the log written since the last checkpoint.
//! - `fsync`:   making one file durable without a whole checkpoint.
//! - `crypto`:  the mount's master keys, and an inode's key when it has one.
//! - `space`:  what `statfs` reports.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::checkpoint::Checkpoint;
use crate::features::Access;
use crate::node::Inode;
use crate::opts::Options;
use crate::sb::SuperBlock;
use crate::summary::{NatEntry, NatJournal, SitEntry, SitJournal};
use crate::uapi::{BLKSIZE, NR_CURSEG_PERSIST_TYPE};

pub mod mount;
pub mod curseg;
pub mod segmap;
pub mod nodes;
pub mod map;
pub mod io;
pub mod dir;
pub mod xattrs;
pub mod space;
pub mod write;
pub mod dnode;
pub mod trim;
pub mod commit;
pub mod fileops;
pub mod dirwrite;
pub mod namei;
pub mod xattr_write;
pub mod discard;
pub mod quotas;
pub mod verify;
pub mod verity_on;
pub mod gc;
pub mod orphan;
pub mod recover;
pub mod fsync;
pub mod crypto;

pub use curseg::{Curseg, Kind, Summary};
pub use dir::DirEntry;
pub use dnode::Holder;
pub use namei::NewInode;
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
    /// The case-folding table this volume resolves names through, when it
    /// folds at all. Loaded once at mount: every lookup needs it, and it is
    /// the same table for the life of the mount.
    pub(crate) casefold: Option<crate::casefold::Casefold>,
    /// Master keys this mount has been given, by the name a policy refers to
    /// one by. Never on the medium: an inode whose key is absent stays
    /// listable and removable, and only its contents and names are withheld.
    pub(crate) fscrypt_keys: BTreeMap<crate::crypto::KeyId, crate::crypto::MasterKey>,
    pub(crate) opts: Options,
    pub(crate) access: Access,
    pub(crate) writable: bool,
    /// The six open logs a write appends to.
    pub(crate) curseg: [Curseg; NR_CURSEG_PERSIST_TYPE],
    /// Node-table entries this mount has changed. These beat the journal and
    /// the table on every read: the medium still holds the old addresses
    /// until a checkpoint retires them.
    pub(crate) nat_dirty: BTreeMap<u32, NatEntry>,
    /// The segment table, loaded whole on the first write.
    pub(crate) sit: Option<Vec<SitEntry>>,
    /// The segment-management state that is not on the medium: the prefree
    /// map, the clock ages are measured against, and the cleaner's cursor.
    pub(crate) segstate: segmap::SegState,
    pub(crate) sit_dirty: BTreeSet<u32>,
    pub(crate) valid_block_count: u64,
    pub(crate) valid_node_count: u32,
    pub(crate) valid_inode_count: u32,
    pub(crate) next_free_nid: u32,
    /// Whether anything is waiting for a checkpoint.
    pub(crate) dirty: bool,
    /// What each quota kind resolved to on this mount.
    pub(crate) quota_setup: [crate::quota::Setup; crate::uapi::MAX_QUOTAS],
    /// Each kind's file header, parsed once.
    pub(crate) quota_info: [Option<crate::quota::Info>; crate::uapi::MAX_QUOTAS],
    /// Records this mount has touched. Read per allocation would make every
    /// write cost a whole quota file.
    pub(crate) dquots: BTreeMap<(usize, u32), crate::quota::Dqblk>,
    pub(crate) dq_dirty: BTreeSet<(usize, u32)>,
    /// The wall clock, in seconds, as the layer above last read it. Grace
    /// periods are absolute expiries, so a decision needs a now.
    pub(crate) clock: u64,
    /// Whether a replay is in progress. The cleaner must not run then: it
    /// moves live blocks, and replay is still reading the chain that names
    /// them.
    pub(crate) recovering: bool,
    /// How many descriptions hold each inode open. An orphan is reclaimed
    /// when this reaches zero, which is what makes the list finite.
    pub(crate) opens: BTreeMap<u32, u32>,
    /// Inodes whose last name is gone but which something still holds open.
    /// They are recorded in the checkpoint so a crash before the last close
    /// does not leak everything they own.
    pub(crate) orphans: BTreeSet<u32>,
    /// Blocks released since the last checkpoint. They are still part of the
    /// checkpoint on the medium, so nothing may be announced to the device
    /// until one replaces it.
    pub(crate) pending_discard: Vec<u32>,
    /// Verity metadata parsed once per inode, and the record of which of its
    /// hash blocks are already known good. Rebuilding it per block would make
    /// the metadata cost scale with the data. Interior mutability because a
    /// read takes `&self` and the cache is what a read fills.
    pub(crate) verity_cache: core::cell::RefCell<crate::verity::info::Cache>,
    /// The certificates a built-in signature's chain must reach, and whether
    /// an unsigned verity file may be read at all.
    pub(crate) verity_policy: crate::verity::Policy,
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

    /// The volume's case-folding table, when it has one. # C: O(1)
    pub fn casefold(&self) -> Option<&crate::casefold::Casefold> { self.casefold.as_ref() }

    /// Tell the volume what time it is.
    ///
    /// Nothing below this layer can read a clock, and a quota grace period is
    /// an absolute expiry: without it a soft limit could never come due.
    /// # C: O(1)
    pub fn set_clock(&mut self, secs: u64) {
        // The first clock this mount is told is the one segment ages count
        // from, so a volume's recorded age advances by how long it has been
        // mounted rather than by where the wall clock happens to start.
        if self.segstate.mounted_clock.is_none() { self.segstate.mounted_clock = Some(secs); }
        self.clock = secs;
    }

    /// Whether anything this mount changed is still only in memory. # C: O(1)
    pub fn is_dirty(&self) -> bool { self.dirty }

    /// Give the medium back, for a caller that wants to mount its bytes
    /// again. A change that only reached memory is invisible here, which is
    /// what makes a remount the proof that a write landed. # C: O(1)
    pub fn into_source(self) -> S { self.source }

    /// The open logs, for a caller checking where a write landed. # C: O(1)
    pub fn logs(&self) -> &[Curseg] { &self.curseg }

    /// Whether `addr` is a main-area block of this volume. # C: O(1)
    pub fn sb_main_contains(&self, addr: u32) -> bool { self.sb.valid_main_blkaddr(addr) }
}

#[cfg(test)]
#[path = "tests/volume.rs"]
mod tests;
