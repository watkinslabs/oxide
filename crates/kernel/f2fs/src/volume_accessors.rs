use super::{Curseg, Volume};
use sectors::SectorSource;
use syscall::errno::Errno;

use crate::checkpoint::Checkpoint;
use crate::features::Access;
use crate::node::Inode;
use crate::opts::Options;
use crate::sb::SuperBlock;

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

    /// The cleaner policy selected for the reclaimed-segment sysfs report.
    /// # C: O(1)
    pub(crate) fn gc_segment_mode(&self) -> usize { self.gc_segment_mode }

    /// Select a valid reclaimed-segment report slot. # C: O(1)
    pub(crate) fn set_gc_segment_mode(&mut self, mode: usize) -> Result<(), Errno> {
        if mode >= crate::stats::counters::gc_mode::MAX { return Err(Errno::Einval); }
        self.gc_segment_mode = mode;
        Ok(())
    }

    /// The live reclaimed-segment total for the selected policy. # C: O(1)
    pub(crate) fn gc_reclaimed_segments(&self) -> u32 {
        self.counters.borrow().gc_reclaimed_segs[self.gc_segment_mode]
    }

    /// Linux's write-zero reset for the selected reclaimed-segment total.
    /// # C: O(1)
    pub(crate) fn reset_gc_reclaimed_segments(&mut self) -> Result<(), Errno> {
        self.counters.borrow_mut().gc_reclaimed_segs[self.gc_segment_mode] = 0;
        Ok(())
    }

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

    /// Consume one timeout fault and return the mode without sleeping while a
    /// filesystem lock is held. # C: O(1)
    pub(crate) fn fault_timeout_mode(&self, f: crate::fault::Fault) -> Option<vfs::FsTimeout> {
        if crate::fault::time_to_inject(&self.fault, f) {
            let timeout = self.fault.timeout();
            return Some(match timeout {
                crate::fault::Timeout::Running => vfs::FsTimeout::Running,
                crate::fault::Timeout::IoSleep => vfs::FsTimeout::IoSleep,
                crate::fault::Timeout::NonIoSleep => vfs::FsTimeout::NonIoSleep,
                crate::fault::Timeout::Runnable => vfs::FsTimeout::Runnable,
                crate::fault::Timeout::None => return None,
            });
        }
        None
    }

    /// Consume one timeout fault at the operation that owns the wait.
    /// # C: O(1), plus the installed kernel timeout owner
    pub(crate) fn fault_timeout(&self, f: crate::fault::Fault) {
        if let Some(mode) = self.fault_timeout_mode(f) { vfs::fs_timeout(mode); }
    }

    /// Change what this mount injects, one field at a time. # C: O(1)
    pub fn set_fault(&self, rate: u32, ty: u32, which: crate::fault::Which)
        -> Result<(), Errno> {
        crate::fault::build(&self.fault, rate, ty, which)
    }
}
