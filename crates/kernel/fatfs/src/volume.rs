//! A mounted volume: name resolution and file reads over the layers below.
//!
//! The medium is a trait rather than a block device, so a whole volume — boot
//! sector, table, directories, long names and file bytes — is exercised end to
//! end against an image in memory. Every layer under this one is already
//! tested in isolation; this is where they are tested TOGETHER, which is the
//! only place an interface mistake between them shows up.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::bpb;
use crate::chain::{self, ChainError};
use crate::dirent::{self, Entry, LongName, ShortEntry, ENTRY_BYTES};
use crate::geometry::{self, FatWidth, Geometry, FAT_START_ENT};

/// Where a volume's bytes come from.
pub trait SectorSource {
    /// Read `buf.len()` bytes starting at sector `sector`. A short read is an
    /// error here: unlike a backing file, a volume's own sectors either exist
    /// or the volume is truncated.
    fn read_sectors(&self, sector: u64, buf: &mut [u8]) -> Result<(), Errno>;
}

/// One name in a directory, with the entry it names.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DirEntry {
    /// The long name when the volume carried a valid one for this entry, the
    /// 8.3 name otherwise.
    pub name: String,
    pub entry: ShortEntry,
}

impl DirEntry {
    /// # C: O(1)
    pub fn is_dir(&self) -> bool { self.entry.is_dir() }
    /// # C: O(1)
    pub fn size(&self) -> u64 { u64::from(self.entry.size) }
}

/// A mounted volume.
pub struct Volume<S: SectorSource> {
    source: S,
    geo: Geometry,
    /// The first table, read once at mount. Every chain walk consults it.
    table: Vec<u8>,
}

impl<S: SectorSource> Volume<S> {
    /// Read the boot sector, resolve the layout, and load the table.
    ///
    /// The table is read whole rather than a sector at a time because a
    /// twelve-bit entry straddles the boundary between two of them.
    /// # C: O(table bytes)
    pub fn mount(source: S) -> Result<Self, Errno> {
        let mut boot = vec![0u8; 512];
        source.read_sectors(0, &mut boot)?;
        let parsed = bpb::parse(&boot).map_err(|e| e.errno())?;
        // A volume declaring a sector larger than the one just read is read
        // again at its own size, or its later fields come from the wrong place.
        let parsed = if parsed.sector_size as usize > boot.len() {
            let mut wider = vec![0u8; parsed.sector_size as usize];
            source.read_sectors(0, &mut wider)?;
            bpb::parse(&wider).map_err(|e| e.errno())?
        } else {
            parsed
        };
        let geo = geometry::resolve(&parsed).map_err(|e| e.errno())?;
        let table_bytes = usize::try_from(u64::from(geo.fat_length) * u64::from(geo.sector_size))
            .map_err(|_| Errno::Einval)?;
        let mut table = vec![0u8; table_bytes];
        source.read_sectors(u64::from(geo.fat_start), &mut table)?;
        Ok(Self { source, geo, table })
    }

    /// # C: O(1)
    pub fn geometry(&self) -> &Geometry { &self.geo }

    /// # C: O(1)
    pub fn width(&self) -> FatWidth { self.geo.width }

    /// Read one cluster's bytes. # C: O(cluster bytes)
    fn read_cluster(&self, cluster: u32, buf: &mut [u8]) -> Result<(), Errno> {
        let sector = self.geo.cluster_sector(cluster).ok_or(Errno::Eio)?;
        self.source.read_sectors(u64::from(sector), buf)
    }

    /// The bytes of a directory, whichever kind it is.
    ///
    /// A fixed root has no cluster chain at all — it is a region of a declared
    /// length — so it is read directly. Treating it as a chain reads table
    /// entry zero, which is the media descriptor, and follows it somewhere
    /// arbitrary.
    /// # C: O(directory bytes)
    fn directory_bytes(&self, cluster: Option<u32>) -> Result<Vec<u8>, Errno> {
        match cluster {
            None => {
                let bytes = usize::try_from(u64::from(self.geo.dir_entries) * ENTRY_BYTES as u64)
                    .map_err(|_| Errno::Einval)?;
                let mut out = vec![0u8; bytes];
                self.source.read_sectors(u64::from(self.geo.dir_start), &mut out)?;
                Ok(out)
            }
            Some(first) => {
                let clusters = chain::walk(&self.geo, &self.table, first).map_err(chain_errno)?;
                let per = usize::try_from(self.geo.cluster_bytes()).map_err(|_| Errno::Einval)?;
                let mut out = vec![0u8; clusters.len() * per];
                for (i, cluster) in clusters.iter().enumerate() {
                    self.read_cluster(*cluster, &mut out[i * per..(i + 1) * per])?;
                }
                Ok(out)
            }
        }
    }

    /// The first cluster of the root directory, or `None` when the volume
    /// keeps its root in a fixed region. # C: O(1)
    fn root_cluster(&self) -> Option<u32> {
        if self.geo.has_fixed_root() { None } else { Some(self.geo.root_cluster) }
    }

    /// List a directory.
    ///
    /// Entries are returned in on-disk order, with deleted ones and the
    /// volume label omitted — a label is not a file, and showing it produces a
    /// directory entry nothing can open.
    /// # C: O(directory bytes)
    pub fn read_dir(&self, cluster: Option<u32>) -> Result<Vec<DirEntry>, Errno> {
        let bytes = self.directory_bytes(cluster)?;
        let mut out = Vec::new();
        let mut long = LongName::new();
        for record in bytes.chunks_exact(ENTRY_BYTES) {
            match dirent::parse(record) {
                None => break,
                Some(Entry::EndOfDirectory) => break,
                // A deleted entry breaks any run in progress: its slots
                // belonged to the name that was removed.
                Some(Entry::Deleted) => long.reset(),
                Some(Entry::LongSlot { ordinal, last, checksum, chars }) =>
                    long.push(ordinal, last, checksum, &chars),
                Some(Entry::Short(entry)) => {
                    let name = long.take(&entry).unwrap_or_else(|| dirent::short_name(&entry));
                    if !entry.is_volume_label() { out.push(DirEntry { name, entry }); }
                }
            }
        }
        Ok(out)
    }

    /// List the root directory. # C: O(directory bytes)
    pub fn read_root(&self) -> Result<Vec<DirEntry>, Errno> { self.read_dir(self.root_cluster()) }

    /// Resolve a slash-separated path from the root.
    ///
    /// Names compare case-insensitively over ASCII, which is what the
    /// filesystem itself does: it has no notion of two files whose names
    /// differ only in case.
    /// # C: O(path components * directory bytes)
    pub fn lookup(&self, path: &str) -> Result<DirEntry, Errno> {
        let mut cluster = self.root_cluster();
        let mut found: Option<DirEntry> = None;
        for component in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            let entries = self.read_dir(cluster)?;
            let hit = entries.into_iter()
                .find(|e| e.name.eq_ignore_ascii_case(component))
                .ok_or(Errno::Enoent)?;
            cluster = Some(hit.entry.cluster);
            found = Some(hit);
        }
        found.ok_or(Errno::Enoent)
    }

    /// Read `buf.len()` bytes of a file from `offset`, returning how many were
    /// read. Reads stop at the file's declared size: the tail of the last
    /// cluster is not part of the file, and returning it would append whatever
    /// the medium last held there.
    /// # C: O(bytes read)
    pub fn read_file(&self, entry: &ShortEntry, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        if entry.is_dir() { return Err(Errno::Eisdir); }
        let size = u64::from(entry.size);
        if offset >= size { return Ok(0); }
        let want = core::cmp::min(buf.len() as u64, size - offset) as usize;
        if want == 0 { return Ok(0); }
        // A zero-length file names no cluster at all, so there is nothing to
        // walk; the early return above already covered it.
        let clusters = chain::walk(&self.geo, &self.table, entry.cluster).map_err(chain_errno)?;
        let per = usize::try_from(self.geo.cluster_bytes()).map_err(|_| Errno::Einval)?;
        let mut scratch = vec![0u8; per];
        let mut done = 0usize;
        while done < want {
            let pos = offset + done as u64;
            let index = usize::try_from(pos / per as u64).map_err(|_| Errno::Eio)?;
            let within = usize::try_from(pos % per as u64).map_err(|_| Errno::Eio)?;
            // The chain is shorter than the size claims: the entry and the
            // table disagree, and the table is the one that owns the data.
            let cluster = *clusters.get(index).ok_or(Errno::Eio)?;
            self.read_cluster(cluster, &mut scratch)?;
            let take = core::cmp::min(per - within, want - done);
            buf[done..done + take].copy_from_slice(&scratch[within..within + take]);
            done += take;
        }
        Ok(done)
    }

    /// Read a whole file. # C: O(file bytes)
    pub fn read_whole(&self, entry: &ShortEntry) -> Result<Vec<u8>, Errno> {
        let mut out = vec![0u8; usize::try_from(entry.size).map_err(|_| Errno::Einval)?];
        let got = self.read_file(entry, 0, &mut out)?;
        out.truncate(got);
        Ok(out)
    }
}

/// A chain failure, as an errno. Every one of them means the volume's own
/// metadata is inconsistent, which is `EIO` rather than a bad request.
/// # C: O(1)
fn chain_errno(err: ChainError) -> Errno {
    match err { ChainError::OutOfRange | ChainError::Cycle | ChainError::TableTooShort => Errno::Eio }
}

/// Whether `cluster` could begin a chain on this volume. # C: O(1)
pub fn plausible_first_cluster(geo: &Geometry, cluster: u32) -> bool {
    cluster >= FAT_START_ENT && cluster < geo.max_cluster
}

#[cfg(test)]
#[path = "volume/tests.rs"]
mod tests;
