//! Mounting an F2FS volume: the VFS-facing filesystem, its inodes and their
//! operations.
//!
//! Everything below this file is pure and already tested against images in
//! memory — including the write path, which is proved by writing an image and
//! mounting its bytes again. This is the adapter, and the only layer that
//! reaches the block layer.
//!
//! Module manifest:
//! - `node`: what an inode of this filesystem is, built from a stored one.
//! - `ops`:  the inode and file operations.
//! - `quota`: the hooks `quotactl(2)` reaches this filesystem through.
//! - `sb`:   `statfs` and the option tail.
//! - `write`: the mutating operations, and the clock they share.
//! - `remount`: reconfiguring a live mount from a new option line.
//! - `devs`:  finding the member devices, and asking each about its zones.
//! - `freeze`: sealing the volume for a snapshot, and resuming after one.
//! - `wp`:     settling the drives' write pointers against the volume.
//! - `data`:   the way back from a dirty data page to this mount.

use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::BlockSource;
use vfs::{InodeRef, KResult, VfsError};

use crate::features::Access;
use crate::opts::Options;
use crate::uapi::BLKSIZE;
use crate::volume::Volume;

pub mod node;
pub mod devs;
pub mod ops;
pub mod quota;
pub mod sb;
pub mod write;
pub mod remount;
pub mod freeze;
pub mod wp;
pub mod data;

/// The one name this filesystem is registered under.
pub const F2FS_NAME: &str = "f2fs";

/// A mounted F2FS filesystem.
pub struct F2fs {
    /// Every member device, in the superblock's order. Kept so freed space
    /// can be announced to the one that holds it: the volume reads and writes
    /// through a sector source that deliberately exposes only those two
    /// operations, and discard is a property of the DEVICE rather than of the
    /// medium abstraction.
    devs: Vec<Arc<dyn block::BlockDevice>>,
    /// One lock: the volume caches the checkpoint and both journals, which
    /// every read consults.
    pub(crate) volume: sync::Spinlock<alloc::boxed::Box<Volume<devs::Medium>>, sync::TaskList>,
    source: String,
    /// Held so the superblock operations can reach the filesystem they belong
    /// to, which the `&self` those operations are asked for cannot.
    me: Weak<F2fs>,
    /// The cleaner and the discard thread, their knobs and their wake points.
    /// Outside the volume lock deliberately: turning a knob must not have to
    /// wait behind a read that is fetching a block.
    bg: Arc<crate::bg::Bg>,
}

impl F2fs {
    /// Mount the volume on `dev`, read-only, naming no option.
    ///
    /// Naming nothing is NOT the build-wide default set: the right number of
    /// logs, the right allocation mode, the right write mode and whether the
    /// device is told about freed blocks all follow from the volume and the
    /// device, and a build-wide answer gets each of them wrong on some volume
    /// and gets it wrong silently. Resolving an empty line is what derives
    /// them — the same path a caller naming options takes, with nothing named.
    /// # C: O(checkpoint bytes)
    pub fn open(dev: Arc<dyn block::BlockDevice>, source: &str) -> KResult<Arc<Self>> {
        Self::open_line(dev, source, false, "")
    }

    /// Mount under an option set.
    ///
    /// A volume whose own features permit only reads mounts READ-ONLY even
    /// when the caller asked to write, and reports that through
    /// [`Self::is_writable`] so the superblock can be marked accordingly.
    /// Reporting writable when the volume is not fails every write at the
    /// first one instead of at the mount.
    /// # C: O(checkpoint bytes)
    #[inline(never)]
    pub fn open_with(dev: Arc<dyn block::BlockDevice>, source: &str, write: bool, opts: Options)
        -> KResult<Arc<Self>> {
        // The volume's own unit is the block, and the source is aimed at it
        // directly: a block address IS the sector number this reads through,
        // so no second unit exists to disagree.
        //
        // The superblock is read through the mounted device alone, because it
        // is what NAMES the other members. Only then can the medium that spans
        // them be built, and the superblock is read again through it — from
        // the same blocks, since member zero's span begins at address zero.
        let probe = BlockSource::new(Arc::clone(&dev)).with_sector_size(BLKSIZE as u32);
        let sb = crate::volume::mount::read_super(&probe).map_err(errno_to_vfs)?;
        let members = devs::open_members(dev, &sb)?;
        let table = crate::devices::DevTable::scan(&sb);
        let reports = devs::zone_reports(&members);
        let src = devs::medium(&members, table, write)?;
        let volume =
            Volume::mount_devices(src, opts, write, &reports).map_err(errno_to_vfs)?;
        if volume.access() == Access::ReadOnly {
            klog::warn::warn_on(true, "f2fs: volume is marked read-only; mounting read-only");
        }
        let source = source.to_string();
        let bg = Arc::new(crate::bg::Bg::new(volume.options().background_gc,
                                             volume.options().discard_unit,
                                             volume.super_block().segs_per_sec));
        let fs = Arc::new_cyclic(|me| Self {
            devs: members,
            volume: sync::Spinlock::new(volume),
            source,
            me: me.clone(),
            bg,
        });
        // Before anything can dirty a page: the mapping refuses to hold a
        // dirty page it has nowhere to send, and everything below writes
        // through it.
        fs.adopt_data_pages();
        // After the replay the volume ran on its way up, and before anything
        // can allocate: a log left standing where the drive will not take its
        // next write fails the FIRST write to it, with nothing to say why.
        // The mount is failed rather than handed out — a volume whose logs
        // cannot be written to is not a mounted filesystem.
        fs.check_and_fix_write_pointers()?;
        // After the mount is reachable, never during it: a thread that woke
        // first would find a filesystem nothing could hand it work through.
        fs.start_background();
        // Same reason, for the same hazard from the other direction: reclaim
        // must not be able to reach a mount that is still being built. From
        // here the three unbounded caches are visible to memory pressure, which
        // is the only thing that ever shrinks them while the mount lives.
        crate::shrink::join(&fs);
        Ok(fs)
    }

    /// Mount from an option LINE, which is what a caller actually has.
    ///
    /// The difference from [`Self::open_with`] is where the defaults come
    /// from: this resolves them against the volume's own shape before the line
    /// is read, so a mount that named nothing gets what THIS volume needs
    /// rather than what the build guessed.
    /// # C: O(checkpoint bytes)
    #[inline(never)]
    pub fn open_line(dev: Arc<dyn block::BlockDevice>, source: &str, write: bool, data: &str)
        -> KResult<Arc<Self>> {
        let discard = dev.supports_discard();
        let keep = Arc::clone(&dev);
        let src = BlockSource::new(dev).with_sector_size(BLKSIZE as u32).writable(write);
        let facts = crate::volume::mount::mount_facts(&src, write, discard)
            .map_err(errno_to_vfs)?;
        let (opts, _) = crate::consistency::resolve(&facts, data).map_err(errno_to_vfs)?;
        Self::open_with(keep, source, write, opts)
    }

    /// The background state this mount's threads share. # C: O(1)
    pub fn bg(&self) -> &Arc<crate::bg::Bg> { &self.bg }

    /// Whether the DEVICE can be told that blocks are no longer needed.
    ///
    /// A property of the device rather than of the volume, which is why it is
    /// read here and not in the volume: it is what decides whether `discard`
    /// is a default worth taking and whether asking for it is a refusal.
    /// # C: O(1)
    pub fn supports_discard(&self) -> bool {
        self.devs.iter().all(|d| d.supports_discard())
    }

    /// Whether this mount ended up writable.
    ///
    /// A mount that asked to write a volume whose own features forbid it, or
    /// a medium that refuses writes, reports false here so the superblock can
    /// be marked read-only — failing every write at the first one instead of
    /// at the mount is the outcome this avoids.
    /// # C: O(1)
    pub fn is_writable(&self) -> bool { self.volume.lock().writable() }

    /// The volume, with its clock set to this instant.
    ///
    /// Every mutation takes the lock through this rather than `volume.lock()`.
    /// Two things are measured against that clock and both fail silently
    /// without it: a segment's age, which decides which segment the cleaner
    /// picks, and a soft quota limit's grace period, which is an absolute
    /// expiry. A volume nobody tells the time to measures every grace against
    /// zero, so none ever comes due, and every segment reads the same age, so
    /// cost-benefit selection degenerates to lowest-numbered.
    /// # C: O(1)
    pub(crate) fn volume_now(&self)
        -> sync::Guard<'_, alloc::boxed::Box<Volume<devs::Medium>>, sync::TaskList>
    {
        let mut v = self.volume.lock();
        v.set_clock(crate::mount::write::now().0);
        v
    }

    /// Push everything to the medium and leave the volume consistent.
    ///
    /// A checkpoint is what turns this mount's out-of-place writes into a
    /// filesystem state; without one the medium still describes the state the
    /// mount started from.
    /// # C: O(dirty blocks)
    pub fn mark_clean(&self) -> KResult<()> { self.checkpoint() }

    /// Write a checkpoint, then announce what it freed.
    ///
    /// The order is the contract. Until the checkpoint lands, every released
    /// block is still referenced by the checkpoint on the medium — announcing
    /// one first destroys the state a crash would recover to.
    /// # C: O(dirty blocks + freed runs)
    pub fn checkpoint(&self) -> KResult<()> {
        let runs = {
            let mut v = self.volume.lock();
            v.commit().map_err(errno_to_vfs)?;
            v.take_discards()
        };
        self.queue_discards(runs);
        Ok(())
    }

    /// Make one file durable, without a whole checkpoint where the volume's
    /// state allows it.
    ///
    /// Which path is taken is not this layer's decision: the volume answers it
    /// from state only it can see, and reports which one it took. The clock is
    /// stamped first because this path can commit, and a checkpoint dates the
    /// segments it writes.
    /// # C: O(nodes the file has) blocks, or O(a checkpoint)
    pub fn sync_file(&self, ino: u32, datasync: bool) -> KResult<()> {
        let runs = {
            let mut v = self.volume_now();
            let r = if datasync { v.fdatasync(ino) } else { v.fsync(ino) };
            let reason = r.map_err(errno_to_vfs)?;
            // ONLY a checkpoint retires what a release freed. The chain path
            // deliberately writes none, so every block this mount has freed is
            // still part of the state a crash recovers to — announcing one to
            // the device destroys exactly that state, and the loss lands on
            // whichever file happened to own the block before it moved.
            if reason.needed() { v.take_discards() } else { alloc::vec::Vec::new() }
        };
        self.queue_discards(runs);
        Ok(())
    }

    /// Tell the device it may forget these runs.
    ///
    /// Best effort by nature: a discard that fails costs nothing but the
    /// space staying marked used on the device, so a failure is not allowed
    /// to fail the checkpoint that already succeeded.
    /// # C: O(runs)
    pub(crate) fn announce_free(&self, runs: &[(u32, u32)]) {
        if runs.is_empty() { return; }
        // The addresses are the VOLUME's, and on a spread volume they mean
        // nothing to any single member. A run handed to the wrong member
        // erases whatever that member happens to hold at the same offset, so
        // every run is split at the member boundaries first and each piece is
        // aimed at the member that owns it.
        let pieces = {
            let v = self.volume.lock();
            let table = v.devices();
            let mut out: alloc::vec::Vec<(usize, u64, u32)> = alloc::vec::Vec::new();
            for &(start, len) in runs {
                let bytes = len as usize * BLKSIZE;
                let Ok(split) = crate::devices::route::split_at(table, u64::from(start), bytes)
                else { continue };
                for r in split { out.push((r.member, r.local, (r.len / BLKSIZE) as u32)); }
            }
            out
        };
        // What was actually handed to a device, request by request. A run the
        // filesystem decided to announce and a device refused to be told about
        // are different things, and the figure that is worth reporting is the
        // traffic that left, not the intent.
        let mut announced: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
        for (i, first_blk, len) in pieces {
            let Some(dev) = self.devs.get(i) else { continue };
            if !dev.supports_discard() { continue; }
            let dev_block = u64::from(dev.block_size().max(1));
            let byte = first_blk * BLKSIZE as u64;
            let bytes = u64::from(len) * BLKSIZE as u64;
            if byte % dev_block != 0 || bytes % dev_block != 0 { continue; }
            let Ok(blocks) = u32::try_from(bytes / dev_block) else { continue };
            let mut req = block::BlockRequest::new_discard(byte / dev_block, blocks);
            if dev.submit_sync(&mut req).is_ok() { announced.push(bytes); }
        }
        if announced.is_empty() { return; }
        let v = self.volume.lock();
        for bytes in announced {
            v.io_account(crate::stats::iostat::Io::FsDiscard, bytes, false);
        }
    }

    /// The root inode. # C: O(1 block)
    pub fn root_inode(self: &Arc<Self>) -> KResult<InodeRef> {
        let ino = self.volume.lock().root_ino();
        node::node_inode(Arc::clone(self), ino)
    }

    /// This mount's option set. # C: O(1)
    pub fn options(&self) -> Options { self.volume.lock().options().clone() }

    /// The device this filesystem was mounted from. # C: O(1)
    pub fn source(&self) -> &str { &self.source }

    /// This mount's section of the status report.
    ///
    /// Rendered here rather than by the caller so the volume lock is taken and
    /// dropped inside this crate: the report samples live counters, and a
    /// caller holding the guard across the render would decide how long a
    /// reader of a debug file holds the filesystem.
    /// # C: O(segments)
    pub fn render_status(&self, index: usize) -> KResult<String> {
        let mut v = self.volume.lock();
        let counters = v.counters();
        let g = crate::stats::General::sample(&mut v, &counters).map_err(errno_to_vfs)?;
        Ok(crate::stats::partition(&g, &self.source, index, crate::mount::write::now().0))
    }
}

/// # C: O(1)
pub fn errno_to_vfs(err: Errno) -> VfsError {
    match err {
        Errno::Einval => VfsError::Einval,
        Errno::Enoent => VfsError::Enoent,
        Errno::Eisdir => VfsError::Eisdir,
        Errno::Enotdir => VfsError::Enotdir,
        Errno::Enotempty => VfsError::Enotempty,
        Errno::Eexist => VfsError::Eexist,
        Errno::Enospc => VfsError::Enospc,
        Errno::Erofs => VfsError::Erofs,
        Errno::Enametoolong => VfsError::Enametoolong,
        Errno::Efbig => VfsError::Efbig,
        Errno::Enomem => VfsError::Enomem,
        Errno::Eopnotsupp => VfsError::Eopnotsupp,
        Errno::Enodata => VfsError::Enodata,
        _ => VfsError::Eio,
    }
}

impl vfs::fs::FileSystem for F2fs {
    fn name(&self) -> &str { F2FS_NAME }
    fn magic(&self) -> u64 { crate::uapi::F2FS_SUPER_MAGIC }
    fn fs_flags(&self) -> vfs::fs::FsFlags { vfs::fs::FsFlags::FS_REQUIRES_DEV }
    fn block_size(&self) -> u32 { BLKSIZE as u32 }
    fn show_options(&self) -> String { { let v = self.volume.lock(); crate::opts::show(v.options(), v.super_block().feature) } }
    fn super_ops(&self) -> Option<Arc<dyn vfs::superblock::SuperOps>> {
        self.me
            .upgrade()
            .map(|fs| Arc::new(sb::F2fsSuperOps { fs }) as Arc<dyn vfs::superblock::SuperOps>)
    }
}

#[cfg(test)]
#[path = "tests/adapter.rs"]
mod tests;
