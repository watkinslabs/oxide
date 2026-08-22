//! What an inode of this filesystem is, and the mode it presents.
//!
//! A FAT inode carries more than the entry it came from: it also carries WHERE
//! that entry's record sits, because every change to a file — its length, its
//! timestamps, its first cluster — is a rewrite of that one record, and
//! searching the directory again for a name already resolved would rewrite
//! whichever record matched second.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use vfs::{mk_mode, FileOps, FileType, InodeBuilder, InodeOps, InodeRef};

use crate::attrs::make_mode;
use crate::dirent::{Record, ShortEntry};
use crate::fatcache::ChainCache;
use crate::ident::{self, DirLocation};
use crate::time::to_unix;
use crate::volume::DirHandle;

use super::{ops::FatOps, FatFs};

/// One inode of a mounted FAT volume.
pub struct FatNode {
    pub(crate) fs: Arc<FatFs>,
    /// The record this inode IS, or `None` for the volume's root, which has
    /// none.
    pub(crate) entry: Option<ShortEntry>,
    pub(crate) location: DirLocation,
    /// The directory this entry was found in, and where its record sits in
    /// it.
    pub(crate) parent: Option<u32>,
    pub(crate) slot: u64,
    /// Records the name occupies, long-name slots included — what a deletion
    /// must free.
    pub(crate) nr_slots: usize,
    /// Remembered chain positions for THIS file. A chain has no index, so
    /// without them every read walks from the first cluster and reading a
    /// large file costs a walk per request.
    pub(crate) cache: sync::Spinlock<ChainCache, sync::TaskList>,
    /// Cluster chain whose last name is gone but whose open inode still owns
    /// it. Zero means no deferred release; FAT data chains start at two.
    release_cluster: AtomicU32,
}

impl FatNode {
    /// This inode as a directory to operate in, or `None` when it is a file.
    ///
    /// The root reports NO record, which is what makes a child's `..` name
    /// cluster zero and what makes a timestamp update on it do nothing —
    /// there is no record of the root anywhere to stamp.
    /// # C: O(1)
    pub(crate) fn as_dir(&self) -> Option<DirHandle> {
        match self.location {
            DirLocation::FixedRoot => Some(DirHandle::root(None)),
            DirLocation::Cluster(c) if self.entry.is_none() => Some(DirHandle::root(Some(c))),
            DirLocation::Cluster(c) => Some(DirHandle::child(c, self.parent, self.slot)),
            DirLocation::Entry { .. } => None,
        }
    }

    /// The directory this entry LIVES in. # C: O(1)
    pub(crate) fn container(&self) -> Option<u32> { self.parent }

    /// Attach the removed name's chain to this inode until eviction. # C: O(1)
    pub(crate) fn defer_release(&self, cluster: u32) {
        self.release_cluster.store(cluster, Ordering::Release);
    }

    /// Take the chain exactly once at the final eviction edge. # C: O(1)
    pub(crate) fn take_release(&self) -> u32 {
        self.release_cluster.swap(0, Ordering::AcqRel)
    }
}

/// Build the inode for one entry.
///
/// The record is decoded rather than the short entry alone, so the case bits
/// and all three timestamps reach the inode. Building it from the short entry
/// would report every file as created at the start of 1980.
/// # C: O(1)
pub(crate) fn node_inode(fs: Arc<FatFs>, entry: Option<ShortEntry>, location: DirLocation,
                         parent: Option<u32>, slot: u64, nr_slots: usize) -> InodeRef {
    let opts = fs.options();
    let ino = ident::inode_number(&location, entry.as_ref());
    build_inode(fs, entry, location, parent, slot, nr_slots, opts, ino)
}

/// Build one uncached inode after the cache miss has been decided. # C: O(1)
fn build_inode(fs: Arc<FatFs>, entry: Option<ShortEntry>, location: DirLocation,
               parent: Option<u32>, slot: u64, nr_slots: usize, opts: crate::opts::Options,
               ino: u64) -> InodeRef {
    let (ftype, perms) = match &entry {
        // The root has no record and therefore no attribute byte; it presents
        // as a directory with the mount's directory mask applied.
        None => (FileType::Directory, make_mode(crate::dirent::ATTR_DIR, &[], &opts)),
        Some(e) if e.is_dir() => (FileType::Directory, make_mode(e.attr, &e.raw_name, &opts)),
        Some(e) => (FileType::Regular, make_mode(e.attr, &e.raw_name, &opts)),
    };
    let size = entry.as_ref().map_or(0, |e| u64::from(e.size));
    let inode_ops: Arc<dyn InodeOps> = Arc::new(FatOps);
    let file_ops: Arc<dyn FileOps> = Arc::new(FatOps);
    let times = stamps(&fs, parent, slot, entry.is_some());
    let node = FatNode { fs, entry, location, parent, slot, nr_slots,
                         cache: sync::Spinlock::new(ChainCache::new()),
                         release_cluster: AtomicU32::new(0) };
    let weak_sb = node.fs.superblock().as_ref().map(Arc::downgrade).unwrap_or_default();
    let mut builder = InodeBuilder::new(ino, mk_mode(ftype, perms), inode_ops, file_ops)
        .sb(weak_sb)
        .size(size)
        .owner(opts.uid, opts.gid)
        .private(Arc::new(node));
    if let Some((atime, mtime, ctime, btime)) = times {
        // FAT has no change time of its own. The reference reports the
        // modification time for both, which is the closest true statement:
        // the only change it records IS a modification.
        builder = builder.times(atime, mtime, ctime).btime(btime);
    }
    builder.build()
}

/// The three readings an entry's record carries, as instants.
///
/// `None` for the root, whose record does not exist — the reference reports
/// the epoch for it rather than inventing a time.
/// # C: O(cluster bytes)
fn stamps(fs: &FatFs, parent: Option<u32>, slot: u64, has_record: bool)
    -> Option<(vfs::timespec::Timespec64, vfs::timespec::Timespec64,
               vfs::timespec::Timespec64, vfs::timespec::Timespec64)> {
    if !has_record { return None; }
    let v = fs.volume.lock();
    let raw = v.read_dir_record(parent, slot).ok()?;
    let record = Record::parse(&raw)?;
    let cfg = &v.options().time;
    let mtime = to_unix(cfg, record.times.modify);
    let atime = to_unix(cfg, crate::time::FatTime {
        time: 0, date: record.times.access_date, cs: 0 });
    let btime = to_unix(cfg, record.times.create);
    Some((atime, mtime, mtime, btime))
}
