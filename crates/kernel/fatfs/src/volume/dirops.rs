//! Creating, deleting and renaming names, over a real volume.
//!
//! Every decision this file could make has already been made in `namei`, which
//! is pure and tested against directory images. What is left here is the part
//! that needs a medium: reading a directory's bytes, growing it, and writing
//! records back in the order `namei` chose.
//!
//! Module manifest:
//! - `create`: a new file, and a new directory with the two entries it starts
//!   with.
//! - `unlink`: removing a name, and the emptiness a directory must have first.
//! - `rename`: moving a name, replacing one, and exchanging two.

use syscall::errno::Errno;

use crate::dirent::{DELETED_FLAG, ENTRY_BYTES};
use crate::namei::{build_group, deletion_order, find_free_run, Group, FreeRun};
use crate::name::flags::SHORT_NAME_LEN;
use crate::time::FatTime;

use super::{DirEntry, SectorSource, Volume};

pub mod create;
pub mod unlink;
pub mod rename;

/// A directory, as everything that changes one needs to see it.
///
/// Two facts, and both are needed: where its CONTENTS are, and where its own
/// RECORD is. The record is what carries the directory's timestamps, and it
/// lives in the parent — a directory does not describe itself. The root has
/// none at all, which is why every timestamp update here is conditional and
/// why the reference's own stamping helper returns early for it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct DirHandle {
    /// First cluster of the contents; `None` when this is a fixed root.
    pub cluster: Option<u32>,
    /// The parent's contents and the offset of this directory's short record
    /// within them. `None` for the root.
    pub record: Option<(Option<u32>, u64)>,
}

impl DirHandle {
    /// A volume's root. # C: O(1)
    pub fn root(cluster: Option<u32>) -> Self { Self { cluster, record: None } }

    /// A subdirectory whose record sits at `slot` of `parent`. # C: O(1)
    pub fn child(cluster: u32, parent: Option<u32>, slot: u64) -> Self {
        Self { cluster: Some(cluster), record: Some((parent, slot)) }
    }

    /// Whether this is the volume's root. # C: O(1)
    pub fn is_root(&self) -> bool { self.record.is_none() }

    /// The cluster a child's `..` entry must name.
    ///
    /// ZERO when this directory is the root, on every width — the root has no
    /// first cluster to name, and a FAT32 root's cluster number is
    /// deliberately not used. A `..` naming it instead would be a second,
    /// different way to reach the root, which every checker reports.
    /// # C: O(1)
    pub fn dotdot_start(&self) -> u32 {
        if self.is_root() { 0 } else { self.cluster.unwrap_or(0) }
    }
}

impl<S: SectorSource> Volume<S> {
    /// The entry `name` names in `dir`. # C: O(directory bytes)
    pub fn find_entry(&self, dir: &DirHandle, name: &str) -> Result<DirEntry, Errno> {
        self.read_dir(dir.cluster)?
            .into_iter()
            .find(|e| self.name_matches(e, name))
            .ok_or(Errno::Enoent)
    }

    /// Build the record group for `name` in `dir`, unique among the eleven-byte
    /// names already there. # C: O(directory bytes)
    pub(crate) fn group_for(&self, dir: &DirHandle, name: &str, is_dir: bool, cluster: u32,
                            now: FatTime) -> Result<Group, Errno> {
        let bytes = self.directory_bytes(dir.cluster)?;
        let mut exists = |candidate: &[u8; SHORT_NAME_LEN]| {
            crate::namei::find_short(&bytes, candidate).is_some()
        };
        build_group(name, is_dir, cluster, now, self.options(), seed(now), &mut exists)
    }

    /// Write a name's records into the directory, growing it when the free run
    /// it needs runs off the end.
    ///
    /// Returns the offset of the SHORT record, which is the entry itself.
    /// Records go out in the order `namei::build` produced them — long-name
    /// slots first, short entry last — so a reader that arrives part-way
    /// through sees free slots, never a name it can open.
    /// # C: O(directory bytes)
    pub(crate) fn add_group(&mut self, dir: &DirHandle, group: &Group) -> Result<u64, Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        let need = group.slots();
        let bytes = self.directory_bytes(dir.cluster)?;
        let at = match find_free_run(&bytes, need)? {
            FreeRun::Found { at } => at,
            FreeRun::Grow { at, have } => {
                let per = self.geometry().cluster_bytes() / ENTRY_BYTES as u64;
                if per == 0 { return Err(Errno::Eio); }
                let missing = (need - have) as u64;
                self.grow_directory(dir.cluster, missing.div_ceil(per) as usize)?;
                at
            }
        };
        self.write_group(dir, at, group)?;
        Ok(group.short_offset(at))
    }

    /// Write the group's records, undoing what landed if one of them fails.
    ///
    /// A half-written group left behind is worse than a failed create: its
    /// slots are occupied by records nothing owns, and the next name that
    /// needs a run of that length skips past them forever.
    /// # C: O(slots)
    fn write_group(&mut self, dir: &DirHandle, at: u64, group: &Group) -> Result<(), Errno> {
        for (i, record) in group.records.iter().enumerate() {
            let slot = at + (i * ENTRY_BYTES) as u64;
            if let Err(e) = self.write_dir_record(dir.cluster, slot, record) {
                let _ = self.mark_deleted(dir, at, i);
                return Err(e);
            }
        }
        Ok(())
    }

    /// Mark `count` records from `at` as free, ignoring the order rules — for
    /// undoing a group that was never published. # C: O(count)
    fn mark_deleted(&mut self, dir: &DirHandle, at: u64, count: usize) -> Result<(), Errno> {
        for i in 0..count { self.free_slot(dir, at + (i * ENTRY_BYTES) as u64)?; }
        Ok(())
    }

    /// Remove a name's whole record group.
    ///
    /// The offsets and their order are `namei::remove`'s: the short entry
    /// first, so the name is gone before anything else changes, then the
    /// long-name slots from the short entry backwards.
    /// # C: O(slots)
    pub(crate) fn remove_group(&mut self, dir: &DirHandle, at: u64, nr_slots: usize)
        -> Result<(), Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        for slot in deletion_order(at, nr_slots) { self.free_slot(dir, slot)?; }
        Ok(())
    }

    /// Mark one record free, leaving the rest of its bytes alone.
    ///
    /// Only the first name byte changes. The reference leaves the rest as it
    /// was, and a recovery tool reads exactly those bytes to work out what the
    /// entry used to be.
    /// # C: O(cluster bytes)
    fn free_slot(&mut self, dir: &DirHandle, slot: u64) -> Result<(), Errno> {
        let mut record = self.read_dir_record(dir.cluster, slot)?;
        record[0] = DELETED_FLAG;
        self.write_dir_record(dir.cluster, slot, &record)
    }

    /// Stamp a directory's own record with a modification time.
    ///
    /// Nothing happens for the root: it has no record to stamp, and the
    /// reference's stamping helper returns early on it for the same reason.
    /// # C: O(cluster bytes)
    pub(crate) fn touch_dir(&mut self, dir: &DirHandle, now: FatTime) -> Result<(), Errno> {
        let Some((parent, slot)) = dir.record else { return Ok(()) };
        let raw = self.read_dir_record(parent, slot)?;
        let entry = crate::dirent::Record::parse(&raw).ok_or(Errno::Eio)?;
        // A directory's record carries a zero size whatever its chain holds,
        // so the size written back is the one already there.
        self.stamp_record(parent, slot, entry.short.cluster, entry.short.size, now)
    }

    /// Release the cluster chain an entry owns, when it owns one.
    ///
    /// Called AFTER the entry naming it is gone, so a chain the release fails
    /// part-way through is one no name reaches — a lost chain, which a check
    /// reclaims — rather than a live name pointing at freed clusters.
    /// # C: O(chain length)
    pub(crate) fn release_chain(&mut self, first: u32) -> Result<(), Errno> {
        if first == 0 { return Ok(()); }
        let geo = self.geo;
        let discard = self.opts.discard && self.source.supports_discard();
        let source = &self.source;
        let mut run_start: Option<u32> = None;
        let mut run_last: Option<u32> = None;
        let submit = |start: Option<u32>, last: Option<u32>| {
            if !discard { return; }
            if let (Some(start), Some(last)) = (start, last) {
                if let (Some(sector), Some(end)) = (geo.cluster_sector(start), geo.cluster_sector(last)) {
                    let count = u64::from(end - sector) + u64::from(geo.sec_per_clus);
                    let _ = source.discard_sectors(u64::from(sector), count);
                }
            }
        };
        crate::cluster_alloc::free_chain_state_with(
            &self.geo, &mut self.table, &mut self.free, first, |cluster| {
                if run_last.map_or(false, |last| cluster != last.saturating_add(1)) {
                    submit(run_start.take(), run_last.take());
                }
                if run_start.is_none() { run_start = Some(cluster); }
                run_last = Some(cluster);
            })?;
        submit(run_start, run_last);
        self.flush_table()?;
        self.flush_fsinfo()
    }
}

/// The starting value for the hashed short-name tail.
///
/// The reference takes it from the clock, and any value works: the search
/// moves off it until the name is free. Taking it from the timestamp the entry
/// is being stamped with keeps this deterministic for a test without making
/// two names created at different instants collide any more often.
/// # C: O(1)
fn seed(now: FatTime) -> u32 { (u32::from(now.date) << 16) | u32::from(now.time) }
