//! Creating a file, and creating a directory.
//!
//! The two differ in one step and its ORDER. A directory needs a cluster of
//! its own holding `.` and `..` before any name points at it, so that cluster
//! is claimed, cleared and filled FIRST and the name is added second — and if
//! the name cannot be added, the cluster goes back. The reverse order
//! publishes a directory whose contents are whatever the medium last held,
//! which is a directory a reader can walk out of into another file's data.

use syscall::errno::Errno;

use crate::dirent::ENTRY_BYTES;
use crate::namei::dot_records;
use crate::time::FatTime;

use super::super::{DirEntry, SectorSource, Volume};
use super::DirHandle;

impl<S: SectorSource> Volume<S> {
    /// Create an empty regular file called `name` in `dir`.
    /// # C: O(directory bytes)
    pub fn create_file(&mut self, dir: &DirHandle, name: &str, now: FatTime)
        -> Result<DirEntry, Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        self.refuse_existing(dir, name)?;
        let group = self.group_for(dir, name, false, 0, now)?;
        let slot = self.add_group(dir, &group)?;
        self.touch_dir(dir, now)?;
        self.entry_at(dir, slot, group.slots(), name)
    }

    /// Create a directory called `name` in `dir`.
    /// # C: O(directory bytes)
    pub fn create_dir(&mut self, dir: &DirHandle, name: &str, now: FatTime)
        -> Result<DirEntry, Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        self.refuse_existing(dir, name)?;
        let cluster = self.new_directory_cluster()?;
        if let Err(e) = self.write_dots(cluster, dir, now) {
            let _ = self.release_chain(cluster);
            return Err(e);
        }
        let outcome = self.group_for(dir, name, true, cluster, now)
            .and_then(|group| Ok((self.add_group(dir, &group)?, group.slots())));
        let (slot, slots) = match outcome {
            Ok(pair) => pair,
            // The name never landed, so nothing reaches the cluster: giving it
            // back is the only way it is ever reclaimed.
            Err(e) => { let _ = self.release_chain(cluster); return Err(e); }
        };
        self.touch_dir(dir, now)?;
        self.entry_at(dir, slot, slots, name)
    }

    /// Write the two entries a directory begins with into its first cluster.
    /// # C: O(cluster bytes)
    fn write_dots(&mut self, cluster: u32, parent: &DirHandle, now: FatTime)
        -> Result<(), Errno> {
        let records = dot_records(cluster, parent.dotdot_start(), now, self.options().long_names);
        let here = DirHandle { cluster: Some(cluster), record: None };
        for (i, record) in records.iter().enumerate() {
            self.write_dir_record(here.cluster, (i * ENTRY_BYTES) as u64, record)?;
        }
        Ok(())
    }

    /// Refuse a name the directory already holds.
    ///
    /// `EEXIST` for a name that is already there. On an 8.3-only mount a
    /// SECOND refusal applies: two different names can format to the same
    /// eleven bytes — a name and the same name with a leading dot — and the
    /// reference reports that collision as `EINVAL`, because the name asked
    /// for is not the name that exists.
    /// # C: O(directory bytes)
    fn refuse_existing(&self, dir: &DirHandle, name: &str) -> Result<(), Errno> {
        if self.find_entry(dir, name).is_ok() { return Err(Errno::Eexist); }
        if self.options().long_names { return Ok(()); }
        let raw = crate::name::msdos::format_name(name.as_bytes(), &self.options().short_rules())?;
        let bytes = self.directory_bytes(dir.cluster)?;
        if crate::namei::find_short(&bytes, &raw).is_some() { return Err(Errno::Einval); }
        Ok(())
    }

    /// The entry a just-written group produced, read back from the medium.
    ///
    /// Read back rather than assembled from what was written: the caller acts
    /// on the record the volume actually holds, so a record that did not land
    /// as intended is an error here instead of a wrong inode later.
    ///
    /// The NAME reported is the one asked for when the entry has long-name
    /// slots, and the eleven bytes as they were stored when it has none — the
    /// same two answers a later listing of the directory gives.
    /// # C: O(cluster bytes)
    fn entry_at(&self, dir: &DirHandle, slot: u64, nr_slots: usize, asked: &str)
        -> Result<DirEntry, Errno> {
        let raw = self.read_dir_record(dir.cluster, slot)?;
        let record = crate::dirent::Record::parse(&raw).ok_or(Errno::Eio)?;
        let name = if nr_slots > 1 {
            alloc::string::String::from(asked)
        } else {
            crate::dirent::short_name_with(&record.short, record.lcase,
                                           self.options().codepage, self.options().shortname)
        };
        Ok(DirEntry { name, entry: record.short, slot, nr_slots })
    }
}
