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

    /// Write `buf` starting at sector `sector`.
    ///
    /// The default refuses. A medium that cannot be written is not an error
    /// to be discovered halfway through a file: a mount asks first, through
    /// [`Self::writable`], and refuses to mount writable at all.
    fn write_sectors(&self, _sector: u64, _buf: &[u8]) -> Result<(), Errno> { Err(Errno::Erofs) }

    /// Whether this medium accepts writes at all. # C: O(1)
    fn writable(&self) -> bool { false }
}

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
    /// Copies of the table this volume carries. Every write updates all.
    fats: u32,
    /// The volume's own dirty flag as found at mount.
    dirty: bool,
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
        Ok(Self { source, geo, table, fats: parsed.fats, dirty })
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
                    let name = long.take(&entry).unwrap_or_else(|| dirent::short_name(&entry));
                    let slot = (index * ENTRY_BYTES) as u64;
                    if !entry.is_volume_label() { out.push(DirEntry { name, entry, slot }); }
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

impl<S: SectorSource> Volume<S> {
    /// Whether this volume may be written — a question about the MEDIUM only.
    ///
    /// A volume its last owner left dirty is still written to. The reference
    /// warns that it was not cleanly unmounted and that a check is due, then
    /// mounts read-write anyway, and that is the usable behaviour: refusing
    /// would leave a user unable to save anything to a stick that was pulled
    /// once. The warning is the caller's to emit; [`Self::was_dirty`] is how
    /// it knows. # C: O(1)
    pub fn writable(&self) -> bool { self.source.writable() }

    /// Was this volume left dirty by whoever had it last? # C: O(1)
    pub fn was_dirty(&self) -> bool { self.dirty }

    /// Free clusters on this volume, from the in-memory table. # C: O(clusters)
    pub fn free_clusters(&self) -> u32 { crate::cluster_alloc::count_free(&self.geo, &self.table) }

    /// One byte of the medium, for a caller checking what actually landed.
    /// # C: O(1 sector)
    pub fn source_bytes(&self, at: usize) -> u8 {
        let sector = at as u64 / u64::from(self.geo.sector_size);
        let within = at % self.geo.sector_size as usize;
        let mut buf = vec![0u8; self.geo.sector_size as usize];
        if self.source.read_sectors(sector, &mut buf).is_err() { return 0; }
        buf[within]
    }

    /// Write one cluster's bytes. # C: O(cluster bytes)
    fn write_cluster(&self, cluster: u32, buf: &[u8]) -> Result<(), Errno> {
        let sector = self.geo.cluster_sector(cluster).ok_or(Errno::Eio)?;
        self.source.write_sectors(u64::from(sector), buf)
    }

    /// Push the in-memory table to EVERY copy on the medium.
    ///
    /// All copies or none: a volume carrying two tables that disagree is one
    /// every checker elsewhere reports, so a failure part-way through is
    /// reported rather than swallowed.
    /// # C: O(table bytes * copies)
    pub fn flush_table(&self) -> Result<(), Errno> {
        for start in crate::volstate::fat_copy_starts(&self.geo, self.fats) {
            self.source.write_sectors(u64::from(start), &self.table)?;
        }
        Ok(())
    }

    /// Set or clear the volume's dirty flag on the medium.
    ///
    /// Marked before the first write and cleared at unmount, so a medium
    /// pulled mid-write tells the next system that read it so.
    ///
    /// A volume ALREADY dirty is left alone, exactly as the reference leaves
    /// it: the flag it carries is the one its last owner set, and clearing it
    /// at this unmount would tell the next reader a check had happened when
    /// none has.
    /// # C: O(1 sector)
    pub fn set_dirty(&self, dirty: bool) -> Result<(), Errno> {
        if self.dirty { return Ok(()); }
        let mut boot = vec![0u8; self.geo.sector_size as usize];
        self.source.read_sectors(0, &mut boot)?;
        crate::volstate::set_dirty(&mut boot, self.geo.width, dirty).ok_or(Errno::Eio)?;
        self.source.write_sectors(0, &boot)
    }

    /// Rewrite one directory record in place.
    ///
    /// The record is written back where it was read from, which is what the
    /// slot carried on every entry is for.
    /// # C: O(cluster bytes)
    fn write_dir_record(&self, dir: Option<u32>, slot: u64, record: &[u8; ENTRY_BYTES])
        -> Result<(), Errno> {
        let per = self.geo.cluster_bytes();
        match dir {
            None => {
                // The fixed root is a flat region; the record's offset is its
                // offset from the region's start.
                let sector = u64::from(self.geo.dir_start) + slot / u64::from(self.geo.sector_size);
                let within = usize::try_from(slot % u64::from(self.geo.sector_size)).map_err(|_| Errno::Eio)?;
                let mut buf = vec![0u8; self.geo.sector_size as usize];
                self.source.read_sectors(sector, &mut buf)?;
                buf[within..within + ENTRY_BYTES].copy_from_slice(record);
                self.source.write_sectors(sector, &buf)
            }
            Some(first) => {
                let clusters = chain::walk(&self.geo, &self.table, first).map_err(chain_errno)?;
                let index = usize::try_from(slot / per).map_err(|_| Errno::Eio)?;
                let within = usize::try_from(slot % per).map_err(|_| Errno::Eio)?;
                let cluster = *clusters.get(index).ok_or(Errno::Eio)?;
                let mut buf = vec![0u8; usize::try_from(per).map_err(|_| Errno::Eio)?];
                self.read_cluster(cluster, &mut buf)?;
                buf[within..within + ENTRY_BYTES].copy_from_slice(record);
                self.write_cluster(cluster, &buf)
            }
        }
    }

    /// Write `data` at `offset` in the file `hit` names, extending its chain
    /// as needed and updating its directory record.
    ///
    /// Returns the file's new size. The order is chosen so that the states an
    /// interrupted write can leave are ones a checker can repair: clusters are
    /// claimed and the table written BEFORE any of the caller's bytes land in
    /// them, and the directory record — which is what makes those bytes part
    /// of the file — is written LAST. A file therefore never points at
    /// clusters the table calls free; the reverse, clusters marked in use that
    /// no file claims, is what `fsck` calls a lost chain and reclaims.
    ///
    /// This is ORDERING, not durability. Nothing here forces the device's own
    /// cache, so a medium pulled mid-write can still have reordered what
    /// reached it. The reference makes the same trade: FAT has no journal.
    /// # C: O(bytes written)
    pub fn write_file(&mut self, dir: Option<u32>, hit: &DirEntry, offset: u64, data: &[u8])
        -> Result<u64, Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        if hit.entry.is_dir() { return Err(Errno::Eisdir); }
        if data.is_empty() { return Ok(u64::from(hit.entry.size)); }
        let per = self.geo.cluster_bytes();
        let end = offset.checked_add(data.len() as u64).ok_or(Errno::Einval)?;
        let need = usize::try_from(end.div_ceil(per)).map_err(|_| Errno::Einval)?;

        let mut first = hit.entry.cluster;
        let mut clusters = if first == 0 {
            alloc::vec::Vec::new()
        } else {
            chain::walk(&self.geo, &self.table, first).map_err(chain_errno)?
        };
        if clusters.len() < need {
            let want = need - clusters.len();
            let hint = *clusters.last().unwrap_or(&0);
            let more = crate::cluster_alloc::allocate(&self.geo, &mut self.table, hint, want,
                                                      clusters.last().copied())?;
            if clusters.is_empty() { first = more[0]; }
            clusters.extend_from_slice(&more);
            // The table reaches the medium before any byte does, so a
            // half-written file never claims a cluster the table calls free.
            self.flush_table()?;
        }

        let mut done = 0usize;
        let mut scratch = vec![0u8; usize::try_from(per).map_err(|_| Errno::Einval)?];
        while done < data.len() {
            let pos = offset + done as u64;
            let index = usize::try_from(pos / per).map_err(|_| Errno::Eio)?;
            let within = usize::try_from(pos % per).map_err(|_| Errno::Eio)?;
            let cluster = *clusters.get(index).ok_or(Errno::Eio)?;
            let take = core::cmp::min(usize::try_from(per).map_err(|_| Errno::Eio)? - within,
                                      data.len() - done);
            // A partial cluster is read before it is written, so the bytes
            // this write does not cover keep their old contents.
            if take < scratch.len() { self.read_cluster(cluster, &mut scratch)?; }
            scratch[within..within + take].copy_from_slice(&data[done..done + take]);
            self.write_cluster(cluster, &scratch)?;
            done += take;
        }

        let size = core::cmp::max(u64::from(hit.entry.size), end);
        let mut updated = hit.entry;
        updated.size = u32::try_from(size).map_err(|_| Errno::Efbig)?;
        updated.cluster = first;
        self.write_dir_record(dir, hit.slot, &dirent::encode_short(&updated))?;
        Ok(size)
    }

    /// Release every cluster a file holds and zero its record's size and
    /// first cluster — `truncate(2)` to nothing.
    /// # C: O(chain length)
    pub fn truncate_file(&mut self, dir: Option<u32>, hit: &DirEntry) -> Result<(), Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        if hit.entry.is_dir() { return Err(Errno::Eisdir); }
        if hit.entry.cluster != 0 {
            crate::cluster_alloc::free_chain(&self.geo, &mut self.table, hit.entry.cluster)?;
            self.flush_table()?;
        }
        let mut updated = hit.entry;
        updated.size = 0;
        updated.cluster = 0;
        self.write_dir_record(dir, hit.slot, &dirent::encode_short(&updated))
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
