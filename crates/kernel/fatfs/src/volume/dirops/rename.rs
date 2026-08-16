//! Moving a name, replacing one, and exchanging two.
//!
//! Rename is where a filesystem loses data if the sequence is wrong, and FAT
//! has no journal to undo a half-done one. The order below is the reference's,
//! step for step, and each step is placed where it is because of what an
//! interruption immediately after it leaves behind:
//!
//! 1. the TARGET record is made to describe the source's data. Both names now
//!    reach the same clusters, which is a duplicate — recoverable, and the
//!    only state in which no data is unreachable;
//! 2. a moved directory's `..` is repointed, while both names still work;
//! 3. the SOURCE name is removed. The duplicate becomes the move;
//! 4. the chain the target used to own is released. It is unreachable by then,
//!    so releasing it frees space rather than orphaning a name.
//!
//! Doing 4 before 1 loses the replaced file's data on any failure after it.
//! Doing 3 before 1 loses the SOURCE's, which is worse: the rename was
//! supposed to keep it.

use syscall::errno::Errno;

use crate::dirent::{Record, RecordTimes};
use crate::namei::find_dotdot;
use crate::time::FatTime;

use super::super::{DirEntry, SectorSource, Volume};
use super::DirHandle;

/// Rename flags this filesystem understands. Anything else is `EINVAL`, which
/// is what the reference answers rather than ignoring a flag the caller relied
/// on.
const SUPPORTED: u32 = vfs::namei::RENAME_NOREPLACE | vfs::namei::RENAME_EXCHANGE;

/// Everything a record says about the FILE, as opposed to its name.
///
/// A rename moves exactly this from one record to another and leaves the
/// name, the case bits and the eleven bytes where they are — which is what
/// makes the moved entry keep the target's name and the source's contents.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct Payload {
    attr: u8,
    cluster: u32,
    size: u32,
    /// Carried unchanged: a rename does not modify the file, so its three
    /// readings are the ones it already had.
    times: RecordTimes,
}

impl<S: SectorSource> Volume<S> {
    /// Rename `old_name` in `old_dir` to `new_name` in `new_dir`.
    /// # C: O(directory bytes)
    pub fn rename(&mut self, old_dir: &DirHandle, old_name: &str, new_dir: &DirHandle,
                  new_name: &str, flags: u32, now: FatTime) -> Result<(), Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        if flags & !SUPPORTED != 0 { return Err(Errno::Einval); }
        if flags & vfs::namei::RENAME_EXCHANGE != 0 {
            return self.exchange(old_dir, old_name, new_dir, new_name, now);
        }
        let old = self.find_entry(old_dir, old_name)?;
        let target = self.find_entry(new_dir, new_name).ok();
        if let Some(t) = &target {
            // A name renamed to itself changes nothing, and going through with
            // it would overwrite the record and then delete it.
            if same_place(old_dir, new_dir, old.slot, t.slot) { return Ok(()); }
            if flags & vfs::namei::RENAME_NOREPLACE != 0 { return Err(Errno::Eexist); }
            self.replaceable(&old, t)?;
        }
        let dotdot = self.dotdot_of(old_dir, new_dir, &old)?;
        let payload = self.payload_of(old_dir, old.slot)?;

        let (slot, replaced) = match target {
            Some(t) => (t.slot, Some(t)),
            None => {
                let group = self.group_for(new_dir, new_name, old.is_dir(), 0, now)?;
                (self.add_group(new_dir, &group)?, None)
            }
        };
        self.put_payload(new_dir, slot, &payload)?;
        if let Some(at) = dotdot { self.set_dotdot(old.entry.cluster, at, new_dir)?; }
        self.remove_group(old_dir, old.group_start(), old.nr_slots)?;
        self.touch_dir(old_dir, now)?;
        if new_dir.cluster != old_dir.cluster { self.touch_dir(new_dir, now)?; }
        // Last, and only once nothing names it.
        if let Some(t) = replaced { self.release_chain(t.entry.cluster)?; }
        Ok(())
    }

    /// Swap two existing names, each keeping its own name and taking the
    /// other's contents.
    ///
    /// Both payloads are read BEFORE either is written. Reading the second
    /// after writing the first hands the first one's contents back and leaves
    /// two names on one file — which is exactly the corruption the exchange
    /// is supposed to be atomic against.
    /// # C: O(directory bytes)
    fn exchange(&mut self, old_dir: &DirHandle, old_name: &str, new_dir: &DirHandle,
                new_name: &str, now: FatTime) -> Result<(), Errno> {
        let a = self.find_entry(old_dir, old_name)?;
        let b = self.find_entry(new_dir, new_name)?;
        if same_place(old_dir, new_dir, a.slot, b.slot) { return Ok(()); }
        let a_dotdot = self.dotdot_of(old_dir, new_dir, &a)?;
        let b_dotdot = self.dotdot_of(new_dir, old_dir, &b)?;
        let pa = self.payload_of(old_dir, a.slot)?;
        let pb = self.payload_of(new_dir, b.slot)?;
        self.put_payload(new_dir, b.slot, &pa)?;
        self.put_payload(old_dir, a.slot, &pb)?;
        if let Some(at) = a_dotdot { self.set_dotdot(a.entry.cluster, at, new_dir)?; }
        if let Some(at) = b_dotdot { self.set_dotdot(b.entry.cluster, at, old_dir)?; }
        self.touch_dir(old_dir, now)?;
        if new_dir.cluster != old_dir.cluster { self.touch_dir(new_dir, now)?; }
        Ok(())
    }

    /// Whether `target` may be replaced by `old`.
    ///
    /// A directory may only replace an empty directory, and a file may not
    /// replace a directory at all — replacing one would leave everything
    /// inside it unreachable and still marked in use.
    /// # C: O(directory bytes)
    fn replaceable(&self, old: &DirEntry, target: &DirEntry) -> Result<(), Errno> {
        if old.is_dir() && !target.is_dir() { return Err(Errno::Enotdir); }
        if !old.is_dir() && target.is_dir() { return Err(Errno::Eisdir); }
        if target.is_dir() { self.require_empty(target)?; }
        Ok(())
    }

    /// Where the `..` record of a MOVING directory sits, when one has to be
    /// repointed at all.
    ///
    /// Only a directory has one, and only a move between different parents
    /// changes it. A directory that has lost its `..` is corrupt — nothing can
    /// walk out of it — so the rename stops rather than moving it and leaving
    /// the entry naming the wrong parent.
    /// # C: O(directory bytes)
    fn dotdot_of(&self, from: &DirHandle, to: &DirHandle, entry: &DirEntry)
        -> Result<Option<u64>, Errno> {
        if !entry.is_dir() || from.cluster == to.cluster { return Ok(None); }
        let bytes = self.directory_bytes(Some(entry.entry.cluster))?;
        Ok(Some(find_dotdot(&bytes).ok_or(Errno::Eio)?))
    }

    /// What the record at `slot` says about the file. # C: O(cluster bytes)
    fn payload_of(&self, dir: &DirHandle, slot: u64) -> Result<Payload, Errno> {
        let record = Record::parse(&self.read_dir_record(dir.cluster, slot)?)
            .ok_or(Errno::Eio)?;
        Ok(Payload { attr: record.short.attr, cluster: record.short.cluster,
                     size: record.short.size, times: record.times })
    }

    /// Make the record at `slot` describe `payload`, keeping its own name and
    /// case bits. # C: O(cluster bytes)
    fn put_payload(&mut self, dir: &DirHandle, slot: u64, payload: &Payload)
        -> Result<(), Errno> {
        let mut record = Record::parse(&self.read_dir_record(dir.cluster, slot)?)
            .ok_or(Errno::Eio)?;
        record.short.attr = payload.attr;
        record.short.cluster = payload.cluster;
        record.short.size = payload.size;
        record.times = payload.times;
        self.write_dir_record(dir.cluster, slot, &record.encode())
    }

    /// Point a moved directory's `..` at its new parent. # C: O(cluster bytes)
    fn set_dotdot(&mut self, contents: u32, at: u64, parent: &DirHandle) -> Result<(), Errno> {
        let mut record = Record::parse(&self.read_dir_record(Some(contents), at)?)
            .ok_or(Errno::Eio)?;
        record.short.cluster = parent.dotdot_start();
        self.write_dir_record(Some(contents), at, &record.encode())
    }
}

/// Whether two entries are the same record of the same directory. # C: O(1)
fn same_place(a: &DirHandle, b: &DirHandle, a_slot: u64, b_slot: u64) -> bool {
    a.cluster == b.cluster && a_slot == b_slot
}
