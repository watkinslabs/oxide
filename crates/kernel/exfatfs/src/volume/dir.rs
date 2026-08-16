//! Reading a directory: entry sets out of the bytes, and finding one by name.
//!
//! A directory ends at the first UNUSED entry, not at the end of its
//! allocation. Everything past that is uninitialised, and reading it as
//! entries produces names that are not there.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::chain::Chain;
use crate::dirent::kind::{class_of, EntryKind};
use crate::dirent::set::{self, EntrySet};
use crate::name::{self, UniName};
use crate::uapi::DENTRY_BYTES;

use super::Volume;

/// One name in a directory.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DirEntry {
    pub set: EntrySet,
    /// The name as a string, decoded once.
    pub name: alloc::string::String,
    /// The directory the set sits in, so an update reaches the bytes it came
    /// from rather than searching for the name a second time and rewriting
    /// whichever set matched second.
    pub dir: Chain,
}

impl DirEntry {
    /// # C: O(1)
    pub fn is_dir(&self) -> bool { self.set.is_dir() }
    /// # C: O(1)
    pub fn size(&self) -> u64 { self.set.size() }
    /// Byte offset of the set's first entry within its directory. # C: O(1)
    pub fn offset(&self) -> u64 { self.set.offset }
}

/// How far into a directory's bytes the live entries reach.
///
/// A directory that has never been shortened ends at its first unused entry;
/// one that has holds deleted sets that are still part of the search space.
/// # C: O(directory bytes)
pub fn live_span(bytes: &[u8]) -> usize {
    for (index, record) in bytes.chunks_exact(DENTRY_BYTES).enumerate() {
        if class_of(record[0]) == EntryKind::Unused { return index * DENTRY_BYTES; }
    }
    bytes.len()
}

/// Decode every live name in a directory's bytes.
///
/// A set that does not decode is SKIPPED rather than ending the listing: one
/// damaged set on a volume must not hide every name after it, which is what
/// stopping would do.
/// # C: O(directory bytes)
pub fn parse_dir(bytes: &[u8], dir: Chain) -> Vec<DirEntry> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + DENTRY_BYTES <= bytes.len() {
        let record = &bytes[at..at + DENTRY_BYTES];
        match class_of(record[0]) {
            EntryKind::Unused => break,
            EntryKind::File => {
                match set::parse(&bytes[at..], at as u64) {
                    Ok(parsed) => {
                        let span = parsed.entries * DENTRY_BYTES;
                        out.push(DirEntry { name: parsed.name(), set: parsed, dir });
                        at += span;
                    }
                    // A set whose own count cannot be trusted advances by one
                    // entry, so the scan cannot be walked off the end by a
                    // corrupt length.
                    Err(_) => at += DENTRY_BYTES,
                }
            }
            _ => at += DENTRY_BYTES,
        }
    }
    out
}

impl<S: SectorSource> Volume<S> {
    /// Every byte of a directory, up to its first unused entry.
    /// # C: O(directory bytes)
    pub fn directory_bytes(&self, dir: &Chain) -> Result<Vec<u8>, Errno> {
        self.chain_bytes(dir)
    }

    /// Every name in a directory. # C: O(directory bytes)
    pub fn read_dir(&self, dir: &Chain) -> Result<Vec<DirEntry>, Errno> {
        Ok(parse_dir(&self.chain_bytes(dir)?, *dir))
    }

    /// Find one name.
    ///
    /// The hash the stream entry carries is checked BEFORE the name, which is
    /// what makes a lookup cheap: a candidate whose hash differs cannot be the
    /// name, whatever its characters are. The name is still compared — the
    /// hash is sixteen bits and collides — so a wrong hash never produces a
    /// wrong match, only a missed one.
    /// # C: O(directory bytes)
    pub fn find_entry(&self, dir: &Chain, name: &str) -> Result<DirEntry, Errno> {
        let wanted = name::resolve(&self.upcase, name, self.opts.keep_last_dots,
                                   name::Usage::Lookup)?;
        self.find_uni(dir, &wanted)
    }

    /// Find one name already encoded. # C: O(directory bytes)
    pub fn find_uni(&self, dir: &Chain, wanted: &UniName) -> Result<DirEntry, Errno> {
        for entry in self.read_dir(dir)? {
            if entry.set.stream.name_hash != wanted.hash { continue; }
            if self.upcase.eq(&entry.set.units, &wanted.units) { return Ok(entry); }
        }
        Err(Errno::Enoent)
    }

    /// Whether a directory holds any name at all. # C: O(directory bytes)
    pub fn dir_is_empty(&self, dir: &Chain) -> Result<bool, Errno> {
        Ok(self.read_dir(dir)?.is_empty())
    }

    /// The run a directory entry's stream names. # C: O(1)
    pub fn chain_of(&self, entry: &EntrySet) -> Chain {
        entry.stream.chain(self.geo.cluster_bytes())
    }

    /// Resolve a slash-separated path from the root.
    /// # C: O(components * directory bytes)
    pub fn lookup(&self, path: &str) -> Result<DirEntry, Errno> {
        let mut dir = self.root;
        let mut found: Option<DirEntry> = None;
        for component in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            let hit = self.find_entry(&dir, component)?;
            dir = self.chain_of(&hit.set);
            found = Some(hit);
        }
        found.ok_or(Errno::Enoent)
    }
}
