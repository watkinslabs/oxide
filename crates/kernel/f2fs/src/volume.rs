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
//! - `nids`:   taking a node id, giving one back, and the cache that holds them.
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
//! - `namei`:  creating, removing and linking names.
//! - `rename`: moving a name, exchanging two, and the whiteout form.
//! - `tmpfile`: an inode no name reaches.
//! - `newcompr`: stamping a new inode's compression settings.
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
//! - `zonewp`: what the segment tables say about a drive's zones.
//! - `ioprio`: the per-file write-priority hint, and the request flags a
//!             write carries because of it.
//! - `iostat`: charging one request to the layer that asked for it.
//! - `blockio`: one block by its address, off the medium or out of the
//!              mount's metadata mapping.
//! - `writeback`: choosing where a file's dirty data pages go, and putting
//!                them there.
//! - `mapped`: what a MAPPING of a file asks for — the fault's fill, charged
//!             to the mapped layer, and the residency questions that must not
//!             fetch.
//! - `readahead`: blocks — data, node and metadata — fetched before a reader
//!                asks for them, one transfer per contiguous run.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::checkpoint::Checkpoint;
use crate::features::Access;
use crate::node::Inode;
use crate::opts::Options;
use crate::sb::SuperBlock;
use crate::summary::{NatEntry, NatJournal, SitEntry, SitJournal};
use crate::uapi::NR_CURSEG_TYPE;

pub mod mount;
pub mod zonewp;
pub mod curseg;
pub mod segmap;
pub mod nodes;
pub mod map;
pub mod io;
pub mod dir;
pub mod xattrs;
pub mod space;
pub mod write;
pub mod nids;
pub mod dnode;
pub mod trim;
pub mod commit;
pub mod fileops;
pub mod dirwrite;
pub mod namei;
pub mod rename;
pub mod tmpfile;
pub mod newcompr;
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
pub mod ioprio;
pub mod iostat;
pub mod blockio;
pub mod writeback;
pub mod nodeback;
pub mod mapped;
pub mod readahead;

pub use curseg::{Curseg, Kind, Summary};
pub use dir::DirEntry;
pub use dnode::Holder;
pub use namei::NewInode;
pub use rename::Rename;
pub use nodes::NodeRef;

/// A mounted volume.
pub struct Volume<S: SectorSource> {
    pub(crate) source: S,
    pub(crate) sb: SuperBlock,
    /// The believed copy's own bytes, where it sits, and whether the other
    /// copy is owed a repair. A superblock change is a patch to these rather
    /// than a re-encode, so a field this build does not parse survives it.
    pub(crate) sb_raw: crate::sbwrite::RawSuper,
    /// Every volume-wide condition this mount is in.
    pub(crate) sbi: crate::sbflags::SbFlags,
    /// The inconsistency kinds this volume has ever shown and the times it
    /// stopped checkpointing, seeded from the superblock and written back
    /// there. Cumulative across mounts, which is what makes it worth having:
    /// a fault that a repair cleared is invisible from the volume's contents.
    pub(crate) errrec: crate::errrec::ErrorRecord,
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
    /// The open logs a write appends to: the six the checkpoint records, and
    /// the pinned log past them, which exists only while mounted.
    pub(crate) curseg: [Curseg; NR_CURSEG_TYPE],
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
    /// The inode numbers this checkpoint epoch has accumulated, by why. Two of
    /// the reasons an `fsync` must write a whole checkpoint are events that
    /// happened to a directory rather than states its blocks show, so they are
    /// recorded here as they happen and retired when a checkpoint lands.
    pub(crate) ino_lists: crate::checkpoint::InoLists,
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
    /// What this mount remembers about where each file's blocks are, and how
    /// long ago they were written.
    ///
    /// Interior mutability for the same reason `verity_cache` has it: a READ
    /// is what fills this and a read takes `&self`. Without the cache every
    /// lookup walks the node tree, which is a block read per level for a
    /// question the previous lookup already answered.
    pub(crate) extents: core::cell::RefCell<crate::extent::Caches>,
    /// Node ids nothing is using. Without it, taking an id means walking the
    /// node table from a cursor and reading a table block per id considered.
    pub(crate) free_nids: crate::freenid::FreeNids,
    /// Whether this mount chooses victims by age, and what it is tuned by.
    pub(crate) atgc: crate::atgc::Atgc,
    /// Running totals nothing can recompute: how many lookups each cache
    /// answered, how many segments each cleaning policy emptied, how many data
    /// blocks have been handed out. Interior mutability because a READ is one
    /// of the things being counted and a read takes `&self` — the same reason
    /// `verity_cache` above needs it.
    pub(crate) counters: core::cell::RefCell<crate::stats::Counters>,
    /// Files between START and COMMIT of an atomic write, by inode number.
    ///
    /// Never on the medium, and that is the promise: an atomic span that a
    /// crash interrupts leaves the file exactly as it was, because none of
    /// what was written is reachable from it — the blocks belong to a COW
    /// inode the checkpoint parks as an orphan.
    pub(crate) atomic: BTreeMap<u32, crate::atomic::AtomicFile>,
    /// The member devices, and which span of block addresses each holds. One
    /// entry for a volume that names none, so nothing below has to ask
    /// whether the volume is spread before it can address a block.
    pub(crate) devs: crate::devices::DevTable,
    /// What the members said about their zones, on a volume laid out for
    /// them. `None` everywhere else, and that `None` is what makes every
    /// usable-space answer collapse to the plain one.
    pub(crate) zoned: Option<crate::zoned::Geometry>,
    /// The I/O-priority hint each open file has been given, by inode number.
    ///
    /// MOUNT state, never on the medium, and that is the contract: the hint
    /// says how this mount should order one file's writes against the rest of
    /// its traffic, which is a statement about this machine's queue and not
    /// about the file's contents. Storing it would carry one machine's
    /// scheduling opinion onto every other machine that mounts the volume, and
    /// an unmount would have no way to retract it.
    ///
    /// Only files with a hint appear here. The default is the absent entry, so
    /// a hint set back to zero is REMOVED rather than recorded as zero — a map
    /// that accumulated an entry per file ever touched would grow with the
    /// number of files rather than with the number of hints.
    pub(crate) ioprio_hint: BTreeMap<u32, u32>,
    /// The compressed blocks this mount has read and kept, when it was asked
    /// to keep them; inert on every other mount. Interior-mutable already, for
    /// the reason the caches above are: a READ is what fills it.
    pub(crate) compress_cache: crate::compress::cache::Cache,
    /// The file DATA pages this mount has read and kept, keyed by inode
    /// number and file offset rather than by block address (`filemap`).
    /// Interior-mutable for the reason the caches above are: a READ is what
    /// fills it, and a read takes `&self`.
    pub(crate) data_cache: alloc::sync::Arc<crate::filemap::Cache>,
    /// The NODE blocks this mount has read or changed, keyed by node id
    /// (`filemap::node`). A node changed here is not on the medium: the
    /// address is chosen when the page is written back, which is what makes a
    /// transaction's nodes one run of the log instead of one block per change.
    pub(crate) node_cache: alloc::sync::Arc<crate::filemap::NodeCache>,
    /// The metadata blocks this mount has read and kept — the checkpoint
    /// packs, both tables and the summary area. Unconditional, unlike the
    /// compressed-block cache above: no mount option turns it off, because
    /// the reference has no option for it either and every mount re-reads the
    /// same handful of table blocks without one.
    /// Whether listing a directory prefetches the node block of every inode
    /// it names. On by default, as the reference has it, and published as a
    /// control because a listing that will not stat what it lists pays for
    /// blocks it never reads.
    pub(crate) readdir_ra: bool,
    pub(crate) meta_cache: crate::checkpoint::cache::Cache,
    /// Failures this mount was asked to inject, and how many each site has
    /// been given. Live state rather than a copy of the option set: a knob
    /// rearms a site without remounting, and the counters are what the report
    /// reads.
    pub(crate) fault: crate::fault::Info,
}

impl<S: SectorSource> Volume<S> {
    /// The volume's superblock. # C: O(1)
    pub fn super_block(&self) -> &SuperBlock { &self.sb }

    /// Every volume-wide condition, as the one word every reporting surface
    /// publishes. Three of the seventeen are the volume's own live state
    /// rather than stored flags, and are folded in here so a second copy of
    /// them cannot exist.
    /// # C: O(1)
    pub fn sb_status(&self) -> u64 {
        self.sbi.word(crate::sbflags::Derived {
            dirty: self.dirty,
            recovering: self.recovering,
            quota_dirty: !self.dq_dirty.is_empty(),
        })
    }

    /// Raise or lower the closing mark, which a flush taken as if the volume
    /// were going away runs under. # C: O(1)
    pub fn set_closing(&mut self, on: bool) { self.sbi.set_closing(on); }

    /// Raise or lower the freezing mark, which a snapshot is taken under.
    /// # C: O(1)
    pub fn set_freezing(&mut self, on: bool) { self.sbi.set_freezing(on); }

    /// Whether a freeze is part way through. # C: O(1)
    pub fn freezing(&self) -> bool { self.sbi.freezing() }

    /// The conditions this mount is in. # C: O(1)
    pub fn sbi_flags(&self) -> &crate::sbflags::SbFlags { &self.sbi }

    /// Take the edited superblock bytes as the volume's own fields.
    ///
    /// Every superblock change ends here, so the parsed view cannot drift from
    /// the bytes that were written. # C: O(superblock bytes)
    pub(crate) fn adopt_super(&mut self) -> Result<(), Errno> {
        self.sb = self.sb_raw.parse().ok_or(Errno::Einval)?;
        Ok(())
    }

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

    /// The member devices and their spans. # C: O(1)
    pub fn devices(&self) -> &crate::devices::DevTable { &self.devs }

    /// What the members said about their zones. # C: O(1)
    pub fn zones(&self) -> Option<&crate::zoned::Geometry> { self.zoned.as_ref() }

    /// Blocks segment `segno` may hold. Every segment on a volume that is not
    /// zoned, and every segment inside its section's zone capacity, holds a
    /// whole segment's worth; the rest hold less or nothing.
    /// # C: O(1)
    pub fn usable_blks_in_seg(&self, segno: u32) -> u32 {
        crate::zoned::usable::usable_blks_in_seg(&self.sb, self.zoned.as_ref(), segno)
    }

    /// Segments of a section that may hold blocks. # C: O(1)
    pub fn usable_segs_in_sec(&self) -> u32 {
        crate::zoned::usable::usable_segs_in_sec(&self.sb, self.zoned.as_ref())
    }

    /// Whether log `log` may hand out another block without opening a new
    /// segment. # C: O(1)
    pub(crate) fn curseg_has_room(&self, log: usize) -> bool {
        let c = &self.curseg[log];
        if c.segno == crate::uapi::NULL_SEGNO { return false; }
        c.has_room_within(self.usable_blks_in_seg(c.segno))
    }

    /// Blocks a section may hold. # C: O(1)
    pub fn cap_blks_per_sec(&self) -> u32 {
        crate::zoned::usable::cap_blks_per_sec(&self.sb, self.zoned.as_ref())
    }

    /// The segment window one `flush device` request should clean.
    /// # C: O(devices)
    pub fn flush_device_window(&self, dev_num: usize, segments: u32, cursor: u32)
        -> Option<(u32, u32)> {
        crate::devices::flush::window(&self.sb, &self.devs, dev_num, segments, cursor)
    }

    /// Which member a file that aliases a device stands for, or why it does
    /// not stand for one. # C: O(devices)
    pub fn alias_device(&self, i: &crate::node::Inode)
        -> Result<usize, crate::devices::alias::AliasError> {
        let zoned = self.zoned.as_ref();
        crate::devices::alias::resolve(
            i,
            self.sb.feature,
            crate::pin::state::is_pinned(i),
            &self.devs,
            |d| zoned.is_some_and(|g| g.dev_is_zoned(d)),
        )
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

    /// Say that something is owed a checkpoint even though nothing changed.
    ///
    /// One caller: a mount about to stop being able to write, which must
    /// leave a checkpoint behind whatever it did. # C: O(1)
    pub fn mark_dirty(&mut self) { self.dirty = true; }

    /// Give the medium back, for a caller that wants to mount its bytes
    /// again. A change that only reached memory is invisible here, which is
    /// what makes a remount the proof that a write landed. # C: O(1)
    pub fn into_source(self) -> S { self.source }

    /// The medium this volume sits on, without taking it.
    ///
    /// A caller that needs to ask the medium something — what it was asked
    /// for, what it holds — must not have to consume the mount to do it.
    /// # C: O(1)
    pub fn source_ref(&self) -> &S { &self.source }

    /// The open logs, for a caller checking where a write landed. # C: O(1)
    pub fn logs(&self) -> &[Curseg] { &self.curseg }

    /// Whether `addr` is a main-area block of this volume.
    ///
    /// Every reader of a stored address goes through here rather than through
    /// the superblock's own bounds test, because this is the one place a mount
    /// asked to fail address checks can make one fail.
    /// # C: O(1)
    pub fn sb_main_contains(&self, addr: u32) -> bool {
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::BlkaddrValidity) {
            return false;
        }
        self.sb.valid_main_blkaddr(addr)
    }

    /// What this mount has accumulated, as one snapshot.
    ///
    /// Copied out rather than borrowed: the report needs the volume MUTABLY to
    /// load the segment table, and a live borrow of the counters would still be
    /// held while it did. A copy cannot go stale the way a stored second count
    /// can, because nothing ever writes back through it.
    /// # C: O(1)
    pub fn counters(&self) -> crate::stats::Counters { *self.counters.borrow() }

    /// What each extent cache is holding: trees, of which zombies, and runs.
    /// # C: O(1)
    #[allow(clippy::type_complexity)]
    pub fn extent_cache_counts(&self) -> ([u64; 2], [u64; 2], [u64; 2]) {
        use crate::extent::Kind;
        let c = self.extents.borrow();
        ([c.tree_count(Kind::Read), c.tree_count(Kind::BlockAge)],
         [c.zombie_count(Kind::Read), c.zombie_count(Kind::BlockAge)],
         [c.node_count(Kind::Read), c.node_count(Kind::BlockAge)])
    }

    /// Bytes each extent cache is holding. # C: O(1)
    pub fn extent_cache_bytes(&self) -> [u64; 2] {
        use crate::extent::Kind;
        let c = self.extents.borrow();
        [c.mem_bytes(Kind::Read), c.mem_bytes(Kind::BlockAge)]
    }

    /// Whether this mount is choosing victims by age. # C: O(1)
    pub fn atgc_enabled(&self) -> bool { self.atgc.enabled }

    /// What age-threshold cleaning is tuned by. # C: O(1)
    pub fn atgc(&self) -> &crate::atgc::Atgc { &self.atgc }

    /// The same, to turn one of its controls. # C: O(1)
    pub fn atgc_mut(&mut self) -> &mut crate::atgc::Atgc { &mut self.atgc }

    /// The extent caches, to turn one of their controls. # C: O(1)
    pub fn extents_mut(&mut self) -> core::cell::RefMut<'_, crate::extent::Caches> {
        self.extents.borrow_mut()
    }

    /// The extent caches, to read one of their controls. # C: O(1)
    pub fn extents(&self) -> core::cell::Ref<'_, crate::extent::Caches> { self.extents.borrow() }

    /// Failures this mount injects, and the counts each site has taken.
    /// # C: O(1)
    pub fn fault_info(&self) -> &crate::fault::Info { &self.fault }

    /// Change what this mount injects, one field at a time. # C: O(1)
    pub fn set_fault(&self, rate: u32, ty: u32, which: crate::fault::Which)
        -> Result<(), Errno> {
        crate::fault::build(&self.fault, rate, ty, which)
    }
}

#[cfg(test)]
#[path = "tests/volume.rs"]
mod tests;
