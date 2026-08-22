//! Creating, deleting and renaming names.
//!
//! Every one of these is TWO changes that must both happen: the file's own MFT
//! record, and the entry in its parent's index. A record with no index entry
//! is a file nothing can name; an index entry with no record is a name that
//! resolves to whatever later takes the record number.
//!
//! Module manifest:
//! - `insert`: putting an entry into a directory's index.
//! - `remove`: taking one out.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::attrib;
use crate::name::FileName;
use crate::record::Reference;
use crate::uapi::*;

use super::dir::DirEntry;
use super::{edit, Volume};

pub mod insert;
pub mod remove;

impl<S: SectorSource> Volume<S> {
    /// Create a file or directory in `parent`. # C: O(record + index bytes)
    fn create_named(&mut self, parent: u64, name: &str, is_dir: bool, now: i64)
        -> Result<DirEntry, Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let units = crate::name::encode(name).ok_or(Errno::Enametoolong)?;
        if self.find_entry(parent, name).is_ok() { return Err(Errno::Eexist); }
        let parent_seq = self.read_record_raw(parent)?.1.sequence;
        let (number, sequence) = self.alloc_record()?;

        let attributes = if is_dir { FILE_ATTRIBUTE_DIRECTORY } else { FILE_ATTRIBUTE_ARCHIVE };
        let fname = FileName {
            parent: Reference { number: parent, sequence: parent_seq },
            create_time: now,
            modify_time: now,
            change_time: now,
            access_time: now,
            alloc_size: 0,
            data_size: 0,
            attributes,
            namespace: FILE_NAME_POSIX,
            units: units.clone(),
        };

        let built = self.build_record(number, sequence, is_dir, &fname, now);
        match built {
            Ok(mut bytes) => {
                self.write_record(number, &mut bytes)?;
            }
            Err(err) => { let _ = self.free_record(number); return Err(err); }
        }

        let reference = Reference { number, sequence };
        if let Err(err) = self.index_insert(parent, &reference, &fname) {
            // The record exists but nothing names it; releasing it is the only
            // state a checker would not have to repair.
            let _ = self.free_record(number);
            return Err(err);
        }
        self.touch_directory(parent, now)?;
        Ok(DirEntry { name: fname.name(), fname, reference })
    }

    /// Lay out a new record's attributes. # C: O(record bytes)
    fn build_record(&mut self, number: u64, sequence: u16, is_dir: bool, fname: &FileName,
                    now: i64) -> Result<Vec<u8>, Errno> {
        let mut bytes = crate::record::format(self.geo.record_size, number, sequence);
        let header = crate::record::parse(&bytes).map_err(|e| e.errno())?;

        let mut std = alloc::vec![0u8; SIZEOF_STD_INFO];
        for (off, value) in [(STD_OFF_CR_TIME, now), (STD_OFF_M_TIME, now),
                             (STD_OFF_C_TIME, now), (STD_OFF_A_TIME, now)] {
            std[off..off + 8].copy_from_slice(&(value as u64).to_le_bytes());
        }
        std[STD_OFF_FA..STD_OFF_FA + 4].copy_from_slice(&fname.attributes.to_le_bytes());
        let id = edit::take_attr_id(&mut bytes);
        let attr = edit::resident(ATTR_STD, &[], id, false, &std);
        edit::insert(&mut bytes, &header, &attr)?;

        let header = crate::record::parse(&bytes).map_err(|e| e.errno())?;
        let id = edit::take_attr_id(&mut bytes);
        let attr = edit::resident(ATTR_NAME, &[], id, true, &crate::name::write_filename(fname));
        edit::insert(&mut bytes, &header, &attr)?;

        let header = crate::record::parse(&bytes).map_err(|e| e.errno())?;
        if is_dir {
            crate::record::set_flags(&mut bytes, header.flags | RECORD_FLAG_DIR);
            let id = edit::take_attr_id(&mut bytes);
            let root = insert::empty_index_root(self.geo.index_size, self.geo.cluster_size);
            let attr = edit::resident(ATTR_ROOT, &I30_NAME, id, false, &root);
            let header = crate::record::parse(&bytes).map_err(|e| e.errno())?;
            edit::insert(&mut bytes, &header, &attr)?;
        } else {
            // An empty file's data is resident and zero-length, which is what
            // every implementation writes: a non-resident attribute over no
            // clusters is not a valid attribute.
            let id = edit::take_attr_id(&mut bytes);
            let attr = edit::resident(ATTR_DATA, &[], id, false, &[]);
            edit::insert(&mut bytes, &header, &attr)?;
        }
        Ok(bytes)
    }

    /// Create an empty file. # C: O(record + index bytes)
    pub fn create_file(&mut self, parent: u64, name: &str, now: i64) -> Result<DirEntry, Errno> {
        self.create_named(parent, name, false, now)
    }

    /// Create a directory. # C: O(record + index bytes)
    pub fn create_dir(&mut self, parent: u64, name: &str, now: i64) -> Result<DirEntry, Errno> {
        self.create_named(parent, name, true, now)
    }

    /// Give an existing file another name. # C: O(record + index bytes)
    pub fn link(&mut self, parent: u64, name: &str, number: u64, now: i64)
        -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let units = crate::name::encode(name).ok_or(Errno::Enametoolong)?;
        if self.find_entry(parent, name).is_ok() { return Err(Errno::Eexist); }
        let parent_seq = self.read_record_raw(parent)?.1.sequence;
        let (original, header) = self.read_record_raw(number)?;
        if header.flags & RECORD_FLAG_DIR != 0 { return Err(Errno::Eperm); }
        if header.hard_links >= NTFS_LINK_MAX { return Err(Errno::Emlink); }

        let attrs = attrib::parse_all(&original, &header);
        let mut fname = attrs.iter().find_map(|attr| {
            if attr.ty != ATTR_NAME { return None; }
            let (start, end) = attr.resident_span()?;
            crate::name::parse_filename(original.get(start..end)?)
        }).ok_or(Errno::Eio)?;
        fname.parent = Reference { number: parent, sequence: parent_seq };
        fname.units = units;
        fname.namespace = FILE_NAME_POSIX;
        fname.change_time = now;

        // Prepare the complete target record before publishing either half.
        // If the parent index cannot accept the name, restoring `original`
        // leaves neither an inflated count nor an unreachable name record.
        let mut changed = original.clone();
        if let Some(std) = attrib::find(&attrs, ATTR_STD, &[]) {
            if let Some((start, end)) = std.resident_span() {
                if end <= changed.len() && end - start >= SIZEOF_STD_INFO {
                    let at = start + STD_OFF_C_TIME;
                    changed[at..at + 8].copy_from_slice(&(now as u64).to_le_bytes());
                }
            }
        }
        let id = edit::take_attr_id(&mut changed);
        let attr = edit::resident(ATTR_NAME, &[], id, true, &crate::name::write_filename(&fname));
        edit::insert(&mut changed, &header, &attr)?;
        crate::record::set_hard_links(&mut changed, header.hard_links + 1);
        self.write_record(number, &mut changed)?;

        let reference = Reference { number, sequence: header.sequence };
        if let Err(err) = self.index_insert(parent, &reference, &fname) {
            let mut original = original;
            self.write_record(number, &mut original)?;
            return Err(err);
        }
        self.touch_directory(parent, now)
    }

    /// Remove a name and the record it names. # C: O(record + index bytes)
    pub fn unlink(&mut self, parent: u64, name: &str, now: i64) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let hit = self.find_entry(parent, name)?;
        if hit.is_dir() { return Err(Errno::Eisdir); }
        self.remove_name(parent, &hit, now)
    }

    /// Remove an empty directory. # C: O(record + index bytes)
    pub fn rmdir(&mut self, parent: u64, name: &str, now: i64) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let hit = self.find_entry(parent, name)?;
        if !hit.is_dir() { return Err(Errno::Enotdir); }
        if !self.dir_is_empty(hit.reference.number)? { return Err(Errno::Enotempty); }
        self.remove_name(parent, &hit, now)
    }

    /// Take a name out of its directory, and the record with it when that was
    /// its last name.
    ///
    /// A record with other names keeps its clusters: those names still resolve
    /// to it, and freeing the clusters would empty a file that is still there.
    /// # C: O(record + index bytes)
    pub(crate) fn remove_name(&mut self, parent: u64, hit: &DirEntry, now: i64)
        -> Result<(), Errno> {
        self.index_remove(parent, &hit.fname.units)?;
        let (bytes, header) = self.read_record_raw(hit.reference.number)?;
        if header.hard_links > 1 {
            let mut bytes = bytes;
            let attrs = attrib::parse_all(&bytes, &header);
            let name_at = attrs.iter().find_map(|attr| {
                if attr.ty != ATTR_NAME { return None; }
                let (start, end) = attr.resident_span()?;
                let fname = crate::name::parse_filename(bytes.get(start..end)?)?;
                if fname.parent == hit.fname.parent && fname.units == hit.fname.units {
                    Some(attr.offset)
                } else {
                    None
                }
            }).ok_or(Errno::Eio)?;
            edit::remove_at(&mut bytes, &header, name_at)?;
            crate::record::set_hard_links(&mut bytes, header.hard_links - 1);
            self.write_record(hit.reference.number, &mut bytes)?;
            return self.touch_directory(parent, now);
        }
        let attrs = attrib::parse_all(&bytes, &header);
        // Every non-resident attribute's clusters go, not just the file's own
        // data: an alternate stream's clusters are leaked otherwise.
        for attr in attrs.iter().filter(|a| a.non_resident && a.is_first_segment()) {
            let runs = self.attribute_runs(&bytes, &attrs, attr)?;
            self.free_runs(&runs)?;
        }
        self.free_record(hit.reference.number)?;
        self.touch_directory(parent, now)
    }

    /// Move a name, within a directory or between two. # C: O(index bytes)
    pub fn rename(&mut self, from: u64, old_name: &str, to: u64, new_name: &str, flags: u32,
                  now: i64) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        if flags & RENAME_WHITEOUT != 0 { return Err(Errno::Einval); }
        if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
            return Err(Errno::Einval);
        }
        if flags & RENAME_EXCHANGE != 0 { return self.exchange(from, old_name, to, new_name, now); }
        let source = self.find_entry(from, old_name)?;
        let target = self.find_entry(to, new_name).ok();
        if let Some(t) = &target {
            if flags & RENAME_NOREPLACE != 0 { return Err(Errno::Eexist); }
            if t.reference == source.reference { return Ok(()); }
            if t.is_dir() != source.is_dir() {
                return Err(if t.is_dir() { Errno::Eisdir } else { Errno::Enotdir });
            }
            if t.is_dir() && !self.dir_is_empty(t.reference.number)? {
                return Err(Errno::Enotempty);
            }
        }
        let units = crate::name::encode(new_name).ok_or(Errno::Enametoolong)?;
        let to_seq = self.read_record_raw(to)?.1.sequence;
        let mut fname = source.fname.clone();
        fname.parent = Reference { number: to, sequence: to_seq };
        fname.units = units;
        fname.change_time = now;

        // The new name goes in before the old comes out, so a failure between
        // them leaves the file reachable twice rather than not at all.
        self.index_insert(to, &source.reference, &fname)?;
        if let Some(t) = &target { self.remove_name(to, t, now)?; }
        self.index_remove(from, &source.fname.units)?;
        self.rewrite_filename(source.reference.number, &source.fname.units, &fname)?;
        self.touch_directory(from, now)?;
        if from != to { self.touch_directory(to, now)?; }
        Ok(())
    }

    /// Swap two names, each keeping its own record. # C: O(index bytes)
    fn exchange(&mut self, from: u64, old_name: &str, to: u64, new_name: &str, now: i64)
        -> Result<(), Errno> {
        let a = self.find_entry(from, old_name)?;
        let b = self.find_entry(to, new_name)?;
        let from_seq = self.read_record_raw(from)?.1.sequence;
        let to_seq = self.read_record_raw(to)?.1.sequence;

        self.index_remove(from, &a.fname.units)?;
        self.index_remove(to, &b.fname.units)?;
        let mut a_new = a.fname.clone();
        a_new.units = b.fname.units.clone();
        a_new.parent = Reference { number: to, sequence: to_seq };
        a_new.change_time = now;
        let mut b_new = b.fname.clone();
        b_new.units = a.fname.units.clone();
        b_new.parent = Reference { number: from, sequence: from_seq };
        b_new.change_time = now;
        self.index_insert(to, &a.reference, &a_new)?;
        self.index_insert(from, &b.reference, &b_new)?;
        self.rewrite_filename(a.reference.number, &a.fname.units, &a_new)?;
        self.rewrite_filename(b.reference.number, &b.fname.units, &b_new)?;
        self.touch_directory(from, now)?;
        if from != to { self.touch_directory(to, now)?; }
        Ok(())
    }

    /// Replace a record's own `$FILE_NAME` attribute after a rename.
    ///
    /// The index entry and the record's attribute both hold the name, and a
    /// rename that changes only the index leaves a record whose own idea of
    /// its name is the old one — which is what a checker repairs by renaming
    /// the file back.
    /// # C: O(record bytes)
    fn rewrite_filename(&mut self, number: u64, old_units: &[u16], fname: &FileName)
        -> Result<(), Errno> {
        let (mut bytes, header) = self.read_record_raw(number)?;
        let attrs = attrib::parse_all(&bytes, &header);
        let target = attrs.iter().find(|a| {
            a.ty == ATTR_NAME
                && a.resident_span().and_then(|(s, e)| bytes.get(s..e))
                    .and_then(crate::name::parse_filename)
                    .is_some_and(|f| f.units == old_units)
        });
        let Some(target) = target else { return Ok(()) };
        let at = target.offset;
        let id = target.id;
        let attr = edit::resident(ATTR_NAME, &[], id, true, &crate::name::write_filename(fname));
        edit::replace_at(&mut bytes, &header, at, &attr)?;
        self.write_record(number, &mut bytes)
    }

    /// Stamp a directory's record with the time it changed. # C: O(record bytes)
    pub(crate) fn touch_directory(&mut self, number: u64, now: i64) -> Result<(), Errno> {
        let (mut bytes, header) = self.read_record_raw(number)?;
        let attrs = attrib::parse_all(&bytes, &header);
        let Some(std) = attrib::find(&attrs, ATTR_STD, &[]) else { return Ok(()) };
        let Some((start, end)) = std.resident_span() else { return Ok(()) };
        if end > bytes.len() || end - start < SIZEOF_STD_INFO { return Ok(()); }
        for off in [STD_OFF_M_TIME, STD_OFF_C_TIME, STD_OFF_A_TIME] {
            let at = start + off;
            bytes[at..at + 8].copy_from_slice(&(now as u64).to_le_bytes());
        }
        self.write_record(number, &mut bytes)
    }
}

/// `renameat2` flags this filesystem acts on.
pub const RENAME_NOREPLACE: u32 = 1;
pub const RENAME_EXCHANGE: u32 = 2;
pub const RENAME_WHITEOUT: u32 = 4;
