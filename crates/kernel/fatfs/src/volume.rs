//! A mounted volume: name resolution and file reads over the layers below.
//!
//! The medium is a trait rather than a block device, so a whole volume — boot
//! sector, table, directories, long names and file bytes — is exercised end to
//! end against an image in memory. Every layer under this one is already
//! tested in isolation; this is where they are tested TOGETHER, which is the
//! only place an interface mistake between them shows up.
//!
//! Module manifest:
//! - `write`:  changing a file's bytes, its length and its record.
//! - `grow`:   giving a directory another cluster, cleared before use.
//! - `dirops`: creating, deleting and renaming names.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::bpb;
use crate::chain::{self, ChainError};
use crate::dirent::{self, Entry, LongName, ShortEntry, ENTRY_BYTES};
use crate::fatcache::{get_cluster, ChainCache, Seek};
use crate::fsinfo::{self, FreeState};
use crate::geometry::{self, FatWidth, Geometry, FAT_START_ENT};
use crate::opts::Options;

pub mod write;
pub mod grow;
pub mod dirops;

pub use dirops::DirHandle;

// A volume's bytes come from `sectors::SectorSource`, which FAT, exFAT and
// NTFS all read through: the read-modify-write rule for a write narrower than
// a device block has one owner rather than one copy per filesystem.
pub use sectors::SectorSource;

/// One name in a directory, with the entry it names.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DirEntry {
    /// The long name when the volume carried a valid one for this entry, the
    /// 8.3 name otherwise.
    pub name: String,
    pub entry: ShortEntry,
    /// Byte offset of the SHORT record within its directory's contents.
    ///
    /// Carried so an update can be written back where it came from. Without
    /// it a writer has to search the directory again for a name it already
    /// found, and would rewrite whichever record matched second.
    pub slot: u64,
    /// Records this name occupies, long-name slots included. A deletion must
    /// free all of them, and a run left behind is a name half-removed.
    pub nr_slots: usize,
}

impl DirEntry {
    /// # C: O(1)
    pub fn is_dir(&self) -> bool { self.entry.is_dir() }
    /// # C: O(1)
    pub fn size(&self) -> u64 { u64::from(self.entry.size) }
    /// Offset of the FIRST record of this name's group. # C: O(1)
    pub fn group_start(&self) -> u64 {
        self.slot - ((self.nr_slots - 1) * ENTRY_BYTES) as u64
    }
    /// Byte offset of the record after this name's short record. # C: O(1)
    pub fn next_pos(&self) -> u64 { self.slot + ENTRY_BYTES as u64 }
}

/// A mounted volume.
pub struct Volume<S: SectorSource> {
    source: S,
    geo: Geometry,
    /// The first table, read once at mount. Every chain walk consults it.
    table: Vec<u8>,
    /// Copies of the table this volume carries. Every write updates all.
    fats: u32,
    /// The volume's own dirty flag as found at mount.
    dirty: bool,
    /// What this mount was asked for.
    opts: Options,
    /// Free-cluster count and allocation hint, carried across every
    /// allocation so the table is scanned once rather than per request.
    free: FreeState,
    /// Where the information sector lives, on a volume that has one.
    fsinfo_sector: Option<u32>,
}

impl<S: SectorSource> Volume<S> {
    /// Read the boot sector, resolve the layout, and load the table.
    ///
    /// The table is read whole rather than a sector at a time because a
    /// twelve-bit entry straddles the boundary between two of them.
    /// # C: O(table bytes)
    pub fn mount(source: S) -> Result<Self, Errno> { Self::mount_with(source, Options::vfat()) }

    /// Mount under a named option set. # C: O(table bytes)
    pub fn mount_with(source: S, opts: Options) -> Result<Self, Errno> {
        let mut boot = vec![0u8; 512];
        source.read_sectors(0, &mut boot)?;
        let parsed = bpb::parse(&boot).map_err(|e| e.errno())?;
        // A volume declaring a sector larger than the one just read is read
        // again at its own size, or its later fields come from the wrong place.
        let (parsed, boot) = if parsed.sector_size as usize > boot.len() {
            let mut wider = vec![0u8; parsed.sector_size as usize];
            source.read_sectors(0, &mut wider)?;
            (bpb::parse(&wider).map_err(|e| e.errno())?, wider)
        } else {
            (parsed, boot)
        };
        let geo = geometry::resolve(&parsed).map_err(|e| e.errno())?;
        let table_bytes = usize::try_from(u64::from(geo.fat_length) * u64::from(geo.sector_size))
            .map_err(|_| Errno::Einval)?;
        let mut table = vec![0u8; table_bytes];
        source.read_sectors(u64::from(geo.fat_start), &mut table)?;
        let dirty = crate::volstate::is_dirty(&boot, geo.width).unwrap_or(false);
        // Only FAT32 keeps an information sector; on the narrower widths the
        // field the sector number would come from is part of something else.
        let fsinfo_sector = if geo.width == FatWidth::Fat32 {
            Some(fsinfo::sector_number(parsed.fsinfo_sector))
        } else {
            None
        };
        let mut vol = Self { source, geo, table, fats: parsed.fats, dirty, opts,
                             free: FreeState::new(), fsinfo_sector };
        vol.adopt_fsinfo();
        Ok(vol)
    }

    /// Take the information sector's two counters, when it has one.
    ///
    /// A failure to read it is not a mount failure: the counters are a hint,
    /// and a volume whose information sector is unreadable still works from a
    /// scan. # C: O(1 sector)
    fn adopt_fsinfo(&mut self) {
        let Some(sector) = self.fsinfo_sector else { return };
        let mut buf = vec![0u8; self.geo.sector_size as usize];
        if self.source.read_sectors(u64::from(sector), &mut buf).is_err() { return; }
        if let Some(info) = fsinfo::parse(&buf) { self.free.adopt(&info, self.opts.usefree); }
        self.free.sanitize(&self.geo);
    }

    /// # C: O(1)
    pub fn geometry(&self) -> &Geometry { &self.geo }

    /// # C: O(1)
    pub fn width(&self) -> FatWidth { self.geo.width }

    /// What this mount was asked for. # C: O(1)
    pub fn options(&self) -> &Options { &self.opts }

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
    pub fn directory_bytes(&self, cluster: Option<u32>) -> Result<Vec<u8>, Errno> {
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
    pub fn root_cluster(&self) -> Option<u32> {
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
        Ok(self.parse_dir(&bytes))
    }

    /// Decode a directory's bytes into its names. # C: O(directory bytes)
    pub fn parse_dir(&self, bytes: &[u8]) -> Vec<DirEntry> {
        let mut out = Vec::new();
        let mut long = LongName::new();
        for (index, record) in bytes.chunks_exact(ENTRY_BYTES).enumerate() {
            match dirent::parse(record) {
                None => break,
                Some(Entry::EndOfDirectory) => break,
                // A deleted entry breaks any run in progress: its slots
                // belonged to the name that was removed.
                Some(Entry::Deleted) => long.reset(),
                Some(Entry::LongSlot { ordinal, last, checksum, chars }) =>
                    long.push(ordinal, last, checksum, &chars),
                Some(Entry::Short(entry)) => {
                    // Taken BEFORE the run is consumed: the count is what says
                    // how many records a deletion of this name must free.
                    let pending = long.pending_slots();
                    let long_name = long.take(&entry);
                    let nr_slots = if long_name.is_some() { pending + 1 } else { 1 };
                    let name = long_name.unwrap_or_else(|| self.short_name(record, &entry));
                    let slot = (index * ENTRY_BYTES) as u64;
                    if !entry.is_volume_label() {
                        out.push(DirEntry { name, entry, slot, nr_slots });
                    }
                }
            }
        }
        out
    }

    /// The 8.3 name a record spells under THIS mount's code page and display
    /// rule, case bits included — which the short entry alone cannot carry.
    /// # C: O(SHORT_NAME_LEN)
    fn short_name(&self, record: &[u8], entry: &ShortEntry) -> String {
        let lcase = dirent::Record::parse(record).map_or(0, |r| r.lcase);
        dirent::short_name_with(entry, lcase, self.opts.codepage, self.opts.shortname)
    }

    /// List the root directory. # C: O(directory bytes)
    pub fn read_root(&self) -> Result<Vec<DirEntry>, Errno> { self.read_dir(self.root_cluster()) }

    /// Whether `name` names `entry`, under this mount's matching rule.
    /// # C: O(name length)
    pub fn name_matches(&self, entry: &DirEntry, name: &str) -> bool {
        if self.opts.long_names {
            return crate::name::compare::eq_with(&entry.name, name, self.opts.case_sensitive(),
                                                 self.opts.iocharset);
        }
        crate::name::msdos::eq(entry.name.as_bytes(), name.as_bytes(), &self.opts.short_rules())
    }

    /// Resolve a slash-separated path from the root. # C: O(components * dir bytes)
    pub fn lookup(&self, path: &str) -> Result<DirEntry, Errno> {
        let mut cluster = self.root_cluster();
        let mut found: Option<DirEntry> = None;
        for component in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            let entries = self.read_dir(cluster)?;
            let hit = entries.into_iter()
                .find(|e| self.name_matches(e, component))
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
    ///
    /// `cache` remembers where the walk got to. A chain has no index, so the
    /// Nth cluster costs N table reads from the start; reading a file
    /// sequentially without one costs a walk per request, which is quadratic
    /// in the file's length.
    /// # C: O(bytes read), after the nearest remembered position
    pub fn read_file_cached(&self, entry: &ShortEntry, cache: &mut ChainCache, offset: u64,
                            buf: &mut [u8]) -> Result<usize, Errno> {
        if entry.is_dir() { return Err(Errno::Eisdir); }
        let size = u64::from(entry.size);
        if offset >= size { return Ok(0); }
        let want = core::cmp::min(buf.len() as u64, size - offset) as usize;
        if want == 0 { return Ok(0); }
        let per = usize::try_from(self.geo.cluster_bytes()).map_err(|_| Errno::Einval)?;
        let mut scratch = vec![0u8; per];
        let mut done = 0usize;
        while done < want {
            let pos = offset + done as u64;
            let index = u32::try_from(pos / per as u64).map_err(|_| Errno::Eio)?;
            let within = usize::try_from(pos % per as u64).map_err(|_| Errno::Eio)?;
            // The chain is shorter than the size claims: the entry and the
            // table disagree, and the table is the one that owns the data.
            let Seek::At { dclus, .. } = get_cluster(&self.geo, &self.table, cache,
                                                     entry.cluster, index)?
                else { return Err(Errno::Eio) };
            self.read_cluster(dclus, &mut scratch)?;
            let take = core::cmp::min(per - within, want - done);
            buf[done..done + take].copy_from_slice(&scratch[within..within + take]);
            done += take;
        }
        Ok(done)
    }

    /// Read without a remembered position, for a caller with no file to keep
    /// one on. # C: O(offset + bytes read)
    pub fn read_file(&self, entry: &ShortEntry, offset: u64, buf: &mut [u8])
        -> Result<usize, Errno> {
        let mut cache = ChainCache::new();
        self.read_file_cached(entry, &mut cache, offset, buf)
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
pub(crate) fn chain_errno(err: ChainError) -> Errno {
    match err { ChainError::OutOfRange | ChainError::Cycle | ChainError::TableTooShort => Errno::Eio }
}

/// Whether `cluster` could begin a chain on this volume. # C: O(1)
pub fn plausible_first_cluster(geo: &Geometry, cluster: u32) -> bool {
    cluster >= FAT_START_ENT && cluster < geo.max_cluster
}

#[cfg(test)]
#[path = "volume/tests.rs"]
mod tests;
