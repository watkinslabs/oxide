//! A mounted volume: everything below this file, driven against a real medium.
//!
//! The medium is a trait rather than a block device, so a whole volume — boot
//! region, tables, bitmap, up-case table, directories and file bytes — is
//! exercised end to end against an image in memory. Every layer under this one
//! is tested in isolation; this is where they are tested TOGETHER, which is
//! the only place a mistake between them shows.
//!
//! Module manifest:
//! - `dir`:    reading a directory's entry sets, and finding one by name.
//! - `alloc`:  claiming, extending, releasing and counting clusters.
//! - `io`:     a file's bytes, in both directions.
//! - `dirops`: creating, deleting and renaming names.
//! - `meta`:   the boot region, the volume flags, the label, `statfs`.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::bitmap::Bitmap;
use crate::boot::{self, Boot};
use crate::chain::{self, Chain};
use crate::dirent::meta::{BitmapEntry, UpcaseEntry, VolumeLabel};
use crate::fat::{FatTable, Reader};
use crate::geometry::{self, Geometry};
use crate::opts::Options;
use crate::uapi::*;
use crate::upcase::{self, UpCase};

pub mod dir;
pub mod alloc_clusters;
pub mod io;
pub mod dirops;
pub mod meta;

pub use dir::DirEntry;
pub use dirops::DirHandle;

/// A mounted volume.
pub struct Volume<S: SectorSource> {
    pub(crate) source: S,
    pub(crate) geo: Geometry,
    /// The boot sector's own bytes, kept so the flags word and the in-use
    /// percentage can be rewritten without re-reading and without disturbing
    /// the boot checksum, which excludes both.
    pub(crate) boot_bytes: Vec<u8>,
    pub(crate) boot: Boot,
    pub(crate) fat: FatTable,
    pub(crate) bitmap: Bitmap,
    /// Where the bitmap lives, so a changed bit can be written back.
    pub(crate) bitmap_chain: Chain,
    pub(crate) upcase: UpCase,
    /// The root directory's clusters.
    pub(crate) root: Chain,
    pub(crate) opts: Options,
    /// The dirty flag as FOUND at mount, before this mount set it.
    pub(crate) was_dirty: bool,
    pub(crate) used_clusters: u32,
    /// Where the next allocation starts looking.
    pub(crate) hint: u32,
    pub(crate) label: Option<VolumeLabel>,
    pub(crate) writable: bool,
}

impl<S: SectorSource> Volume<S> {
    /// Read the boot region, resolve the layout, and load the three structures
    /// nothing else can proceed without: the table, the bitmap and the up-case
    /// table.
    ///
    /// The order matters. The bitmap and up-case entries live in the ROOT
    /// directory, so the root has to be readable before either is found — and
    /// the root is read through the table, which is why the table is loaded
    /// first.
    /// # C: O(table + bitmap + up-case bytes)
    pub fn mount_with(source: S, opts: Options) -> Result<Self, Errno> {
        let mut first = vec![0u8; MIN_BOOT_BYTES];
        source.read_sectors(0, &mut first)?;
        let parsed = boot::parse(&first).map_err(|e| e.errno())?;
        // A volume declaring a sector wider than the one just read is read
        // again at its own size, or the region checksum covers the wrong span.
        let sector_size = 1usize << parsed.sect_size_bits;
        let boot_bytes = if sector_size > first.len() {
            let mut wider = vec![0u8; sector_size];
            source.read_sectors(0, &mut wider)?;
            wider
        } else {
            first
        };
        let geo = geometry::resolve(&parsed);

        let table_bytes = usize::try_from(u64::from(geo.fat_sectors) << geo.sector_bits)
            .map_err(|_| Errno::Einval)?;
        let mut table = vec![0u8; table_bytes];
        source.read_sectors(u64::from(geo.fat_start), &mut table)?;
        let fat = FatTable::new(table);

        // The root directory is a chained run with no recorded length, so its
        // length is counted by walking.
        let root_len = chain::count(&geo, &Reader { table: &fat, geo: &geo }, geo.root_cluster)?;
        if root_len == 0 { return Err(Errno::Einval); }
        let root = Chain::new(geo.root_cluster, root_len, ALLOC_FAT_CHAIN);

        let mut vol = Self {
            source,
            geo,
            boot_bytes,
            boot: parsed,
            fat,
            // Placeholders: neither is usable until the root names where the
            // real ones live, and the root cannot be read without the table.
            bitmap: Bitmap::new(Vec::new(), 0),
            bitmap_chain: Chain::empty(),
            upcase: upcase::builtin(),
            root,
            opts,
            was_dirty: boot::is_dirty(&parsed),
            used_clusters: 0,
            hint: FIRST_CLUSTER,
            label: None,
            writable: false,
        };
        vol.load_volume_structures()?;
        vol.writable = vol.source.writable();
        Ok(vol)
    }

    /// Find the bitmap, up-case table and label in the root, and load them.
    /// # C: O(root bytes + bitmap + up-case bytes)
    fn load_volume_structures(&mut self) -> Result<(), Errno> {
        let root = self.root;
        let bytes = self.chain_bytes(&root)?;
        let mut bitmap_entry: Option<BitmapEntry> = None;
        let mut upcase_entry: Option<UpcaseEntry> = None;
        for record in bytes.chunks_exact(DENTRY_BYTES) {
            match record[0] {
                TYPE_UNUSED => break,
                TYPE_BITMAP if bitmap_entry.is_none() =>
                    bitmap_entry = crate::dirent::meta::parse_bitmap(record),
                TYPE_UPCASE if upcase_entry.is_none() =>
                    upcase_entry = crate::dirent::meta::parse_upcase(record),
                TYPE_VOLUME if self.label.is_none() =>
                    self.label = crate::dirent::meta::parse_label(record),
                _ => {}
            }
        }
        // A volume with no allocation bitmap cannot say which clusters are
        // free, so nothing may be allocated on it and nothing may be trusted
        // about what is: this is a refusal, not a degraded mount.
        let bitmap_entry = bitmap_entry.ok_or(Errno::Einval)?;
        let want = crate::bitmap::bytes_for(self.geo.data_clusters());
        if bitmap_entry.size < want { return Err(Errno::Einval); }
        let bitmap_chain = self.chain_for(bitmap_entry.start_cluster, bitmap_entry.size,
                                          ALLOC_NO_FAT_CHAIN);
        // The bytes are kept at the length the CLUSTERS give, not the length
        // the entry declares: a bit is written back a whole sector at a time,
        // and a bitmap truncated to its declared size has no last sector to
        // write. Which bits are meaningful is the cluster count's answer, not
        // the buffer length's.
        let raw = self.chain_bytes(&bitmap_chain)?;
        if (raw.len() as u64) < want { return Err(Errno::Einval); }
        self.bitmap = Bitmap::new(raw, self.geo.data_clusters());
        self.bitmap_chain = bitmap_chain;
        self.used_clusters = self.bitmap.used();

        // A volume with no up-case entry folds by the built-in rules; that is
        // a malformed volume, and refusing it would make a medium unreadable
        // that every other implementation reads.
        if let Some(entry) = upcase_entry {
            let chain = self.chain_for(entry.start_cluster, entry.size, ALLOC_NO_FAT_CHAIN);
            let mut raw = self.chain_bytes(&chain)?;
            raw.truncate(usize::try_from(entry.size).map_err(|_| Errno::Einval)?);
            match upcase::load(&raw, entry.checksum) {
                Ok(table) => self.upcase = table,
                Err(_) => {
                    klog::warn::warn_on(true,
                        "exfat: up-case table is invalid; folding by the built-in rules");
                }
            }
        }
        Ok(())
    }

    /// The run a start cluster and byte length name. # C: O(1)
    pub(crate) fn chain_for(&self, start: u32, bytes: u64, flags: u8) -> Chain {
        if start == 0 || bytes == 0 { return Chain::empty(); }
        Chain::new(start, self.geo.clusters_for(bytes), flags)
    }

    /// A reader over the table, with the volume's own rules applied. # C: O(1)
    pub(crate) fn fat_reader(&self) -> Reader<'_> { Reader { table: &self.fat, geo: &self.geo } }

    /// # C: O(1)
    pub fn geometry(&self) -> &Geometry { &self.geo }

    /// Give the medium back, so a test can mount the same image again and
    /// read what the writes actually laid down rather than what this mount
    /// remembers. # C: O(1)
    pub fn into_source(self) -> S { self.source }

    /// # C: O(1)
    pub fn options(&self) -> &Options { &self.opts }

    /// # C: O(1)
    pub fn upcase(&self) -> &UpCase { &self.upcase }

    /// # C: O(1)
    pub fn writable(&self) -> bool { self.writable }

    /// Whether the volume's last owner left it dirty. # C: O(1)
    pub fn was_dirty(&self) -> bool { self.was_dirty }

    /// The volume's label, if it carries one. # C: O(1)
    pub fn label(&self) -> Option<&VolumeLabel> { self.label.as_ref() }

    /// The root directory's clusters. # C: O(1)
    pub fn root_chain(&self) -> Chain { self.root }

    /// Read one cluster. # C: O(cluster bytes)
    pub(crate) fn read_cluster(&self, cluster: u32, buf: &mut [u8]) -> Result<(), Errno> {
        let sector = self.geo.cluster_sector(cluster).ok_or(Errno::Eio)?;
        self.source.read_sectors(sector, buf)
    }

    /// Write one cluster. # C: O(cluster bytes)
    pub(crate) fn write_cluster(&self, cluster: u32, buf: &[u8]) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let sector = self.geo.cluster_sector(cluster).ok_or(Errno::Eio)?;
        self.source.write_sectors(sector, buf)
    }

    /// Every byte of a run, in order. # C: O(run bytes)
    pub(crate) fn chain_bytes(&self, chain: &Chain) -> Result<Vec<u8>, Errno> {
        let clusters = chain::walk(&self.geo, &self.fat_reader(), chain)?;
        let per = usize::try_from(self.geo.cluster_bytes()).map_err(|_| Errno::Einval)?;
        let mut out = vec![0u8; clusters.len() * per];
        for (i, cluster) in clusters.iter().enumerate() {
            self.read_cluster(*cluster, &mut out[i * per..(i + 1) * per])?;
        }
        Ok(out)
    }

    /// Read a span of a run's bytes. # C: O(len)
    pub(crate) fn read_at(&self, chain: &Chain, offset: u64, buf: &mut [u8])
        -> Result<(), Errno> {
        let per = self.geo.cluster_bytes();
        let mut done = 0usize;
        let mut scratch = vec![0u8; usize::try_from(per).map_err(|_| Errno::Einval)?];
        while done < buf.len() {
            let pos = offset + done as u64;
            let index = u32::try_from(pos / per).map_err(|_| Errno::Eio)?;
            let within = usize::try_from(pos % per).map_err(|_| Errno::Eio)?;
            let cluster = chain::cluster_at(&self.geo, &self.fat_reader(), chain, index)?;
            self.read_cluster(cluster, &mut scratch)?;
            let take = core::cmp::min(scratch.len() - within, buf.len() - done);
            buf[done..done + take].copy_from_slice(&scratch[within..within + take]);
            done += take;
        }
        Ok(())
    }

    /// Write a span of a run's bytes, reading back whatever a partial cluster
    /// would otherwise lose. # C: O(len)
    pub(crate) fn write_at(&self, chain: &Chain, offset: u64, buf: &[u8]) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let per = self.geo.cluster_bytes();
        let mut done = 0usize;
        let mut scratch = vec![0u8; usize::try_from(per).map_err(|_| Errno::Einval)?];
        while done < buf.len() {
            let pos = offset + done as u64;
            let index = u32::try_from(pos / per).map_err(|_| Errno::Eio)?;
            let within = usize::try_from(pos % per).map_err(|_| Errno::Eio)?;
            let cluster = chain::cluster_at(&self.geo, &self.fat_reader(), chain, index)?;
            let take = core::cmp::min(scratch.len() - within, buf.len() - done);
            // A write covering the whole cluster does not need what was there;
            // anything narrower does, or the bytes either side are lost.
            if within != 0 || take != scratch.len() { self.read_cluster(cluster, &mut scratch)?; }
            scratch[within..within + take].copy_from_slice(&buf[done..done + take]);
            self.write_cluster(cluster, &scratch)?;
            done += take;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/volume.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/write.rs"]
mod write_tests;
