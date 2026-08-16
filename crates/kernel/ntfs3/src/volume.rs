//! A mounted volume: everything below this file, driven against a real medium.
//!
//! Mounting NTFS is circular and that circularity is the whole difficulty. The
//! MFT is a FILE, so where its records are is recorded in an MFT record — the
//! first one — which has to be read before the table it describes can be
//! reached. The order below is the only one that works: boot sector, the first
//! record read at the offset the boot sector names, that record's `$DATA`
//! runlist, and only then every other record through it.
//!
//! Module manifest:
//! - `mft`:    reading and writing records, with their update sequences.
//! - `data`:   an attribute's bytes, resident, non-resident, sparse and
//!             compressed.
//! - `dir`:    a directory's index, and finding one name in it.
//! - `inode`:  what one record adds up to: type, size, times, streams.
//! - `alloc`:  claiming and releasing clusters and records.
//! - `edit`:   adding, replacing and removing a record's attributes.
//! - `write`:  a file's bytes, and the moment its data leaves the record.
//! - `dirops`: creating, deleting and renaming names.
//! - `meta`:   the volume flags, the label, `statfs`.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::attrib::{self, Body};
use crate::bitmap::Bitmap;
use crate::boot::{self, Boot, Geometry};
use crate::opts::Options;
use crate::record;
use crate::run::{self, Runs};
use crate::uapi::*;
use crate::upcase::{self, UpCase};

pub mod mft;
pub mod data;
pub mod dir;
pub mod inode;
pub mod alloc_clusters;
pub mod dirops;
pub mod edit;
pub mod write;
pub mod meta;

pub use dir::DirEntry;
pub use inode::NodeInfo;

/// A mounted volume.
pub struct Volume<S: SectorSource> {
    pub(crate) source: S,
    pub(crate) geo: Geometry,
    /// The boot sector's own fields, kept so a caller can report what the
    /// volume declared rather than what the geometry made of it.
    pub(crate) boot: Boot,
    /// The MFT's own clusters, read out of its first record.
    pub(crate) mft_runs: Runs,
    /// Records the MFT holds.
    pub(crate) mft_records: u64,
    /// Which records are in use, from the MFT's own `$BITMAP`.
    pub(crate) mft_bitmap: Bitmap,
    /// Which clusters are in use, from `$Bitmap`.
    pub(crate) cluster_bitmap: Bitmap,
    pub(crate) upcase: UpCase,
    pub(crate) opts: Options,
    pub(crate) label: Vec<u16>,
    pub(crate) volume_flags: u16,
    pub(crate) version: (u8, u8),
    pub(crate) writable: bool,
    /// Where the next cluster allocation starts looking.
    pub(crate) cluster_hint: u64,
    /// Where the next record allocation starts looking.
    pub(crate) record_hint: u64,
}

impl<S: SectorSource> Volume<S> {
    /// Read the boot sector and the structures nothing else can proceed
    /// without. # C: O(MFT record + bitmap bytes)
    pub fn mount_with(source: S, opts: Options) -> Result<Self, Errno> {
        let mut sector = vec![0u8; BOOT_BYTES];
        source.read_sectors(0, &mut sector)?;
        let parsed = boot::parse(&sector).map_err(|e| e.errno())?;
        let geo = boot::resolve(&parsed).map_err(|e| e.errno())?;

        let mut vol = Self {
            source,
            geo,
            boot: parsed,
            // The MFT's own runs are not known yet; its first record sits at
            // the offset the boot sector names and is read directly.
            mft_runs: Runs::new(),
            mft_records: 1,
            mft_bitmap: Bitmap::new(Vec::new(), 0),
            cluster_bitmap: Bitmap::new(Vec::new(), 0),
            upcase: upcase::builtin(),
            opts,
            label: Vec::new(),
            volume_flags: 0,
            version: (0, 0),
            writable: false,
            cluster_hint: 0,
            record_hint: MFT_REC_USER,
        };
        vol.bootstrap_mft()?;
        vol.load_volume_structures()?;
        vol.writable = vol.source.writable();
        Ok(vol)
    }

    /// Read the MFT's first record and adopt the runlist it carries.
    ///
    /// Until this succeeds no record but the first can be reached, because a
    /// record's position is a position within the MFT and the MFT is a file
    /// whose clusters this runlist names.
    /// # C: O(record bytes)
    fn bootstrap_mft(&mut self) -> Result<(), Errno> {
        let mut bytes = vec![0u8; self.geo.record_size as usize];
        self.read_bytes(self.geo.mft_offset, &mut bytes)?;
        crate::fixup::post_read(&mut bytes, false).map_err(|e| e.errno())?;
        let header = record::parse(&bytes).map_err(|e| e.errno())?;
        let attrs = attrib::parse_all(&bytes, &header);

        let mut runs = Runs::new();
        for seg in attrib::segments(&attrs, ATTR_DATA, &[]) {
            let Body::NonResident { svcn, evcn, .. } = seg.body else { return Err(Errno::Eio) };
            let (start, end) = seg.run_span().ok_or(Errno::Eio)?;
            let part = run::unpack(&bytes[start..end], svcn, evcn, self.geo.clusters)
                .map_err(|e| e.errno())?;
            for r in part.runs { runs.push(r); }
        }
        if runs.runs.is_empty() { return Err(Errno::Eio); }
        let data = attrib::find(&attrs, ATTR_DATA, &[]).ok_or(Errno::Eio)?;
        self.mft_records = data.data_size() >> self.geo.record_bits;
        self.mft_runs = runs;

        // The MFT's own bitmap says which records are live. Without it a scan
        // cannot tell a free record from one whose header was never written.
        let bits = self.mft_records;
        let bitmap = match attrib::find(&attrs, ATTR_BITMAP, &[]) {
            Some(attr) => self.attribute_bytes(&bytes, &attrs, attr)?,
            None => Vec::new(),
        };
        let bitmap = if bitmap.is_empty() { vec![0xFFu8; crate::bitmap::bytes_for(bits) as usize] }
                     else { bitmap };
        self.mft_bitmap = Bitmap::new(bitmap, bits);
        Ok(())
    }

    /// Read `$Bitmap`, `$UpCase` and `$Volume`. # C: O(bitmap + up-case bytes)
    fn load_volume_structures(&mut self) -> Result<(), Errno> {
        // $Bitmap: one bit per cluster, and the only truth about which are
        // free. A volume without it cannot be allocated on.
        let (bytes, attrs) = self.read_record(MFT_REC_BITMAP)?;
        let attr = attrib::find(&attrs, ATTR_DATA, &[]).ok_or(Errno::Eio)?;
        let raw = self.attribute_bytes(&bytes, &attrs, attr)?;
        if (raw.len() as u64) < crate::bitmap::bytes_for(self.geo.clusters) {
            return Err(Errno::Eio);
        }
        self.cluster_bitmap = Bitmap::new(raw, self.geo.clusters);

        // $UpCase decides which names collide AND the order every directory
        // is sorted in, so a descent under a different fold walks to the wrong
        // child. A volume whose copy is unreadable folds by the built-in rules
        // rather than refusing to mount.
        if let Ok((bytes, attrs)) = self.read_record(MFT_REC_UPCASE) {
            if let Some(attr) = attrib::find(&attrs, ATTR_DATA, &[]) {
                if let Ok(raw) = self.attribute_bytes(&bytes, &attrs, attr) {
                    self.upcase = upcase::load(&raw);
                }
            }
        }

        if let Ok((bytes, attrs)) = self.read_record(MFT_REC_VOL) {
            if let Some(attr) = attrib::find(&attrs, ATTR_LABEL, &[]) {
                if let Ok(raw) = self.attribute_bytes(&bytes, &attrs, attr) {
                    self.label = raw.chunks_exact(2)
                        .map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
                }
            }
            if let Some(attr) = attrib::find(&attrs, ATTR_VOL_INFO, &[]) {
                if let Ok(raw) = self.attribute_bytes(&bytes, &attrs, attr) {
                    if raw.len() >= SIZEOF_VOLUME_INFO {
                        self.version = (raw[VOLINFO_OFF_MAJOR], raw[VOLINFO_OFF_MINOR]);
                        self.volume_flags =
                            u16::from_le_bytes([raw[VOLINFO_OFF_FLAGS],
                                                raw[VOLINFO_OFF_FLAGS + 1]]);
                    }
                }
            }
        }
        Ok(())
    }

    /// # C: O(1)
    pub fn geometry(&self) -> &Geometry { &self.geo }

    /// What the boot sector declared, before it was resolved. # C: O(1)
    pub fn boot(&self) -> &Boot { &self.boot }

    /// # C: O(1)
    pub fn options(&self) -> &Options { &self.opts }

    /// # C: O(1)
    pub fn upcase(&self) -> &UpCase { &self.upcase }

    /// # C: O(1)
    pub fn writable(&self) -> bool { self.writable }

    /// Whether the volume's last owner left it dirty. # C: O(1)
    pub fn was_dirty(&self) -> bool { self.volume_flags & VOLUME_FLAG_DIRTY != 0 }

    /// Records the MFT holds. # C: O(1)
    pub fn mft_records(&self) -> u64 { self.mft_records }

    /// Refuse every write through this mount from here on.
    ///
    /// A volume whose journal has not been replayed is mounted read-only
    /// rather than refused: its contents are still readable, and writing to it
    /// loses whatever the journal was about to redo.
    /// # C: O(1)
    pub fn set_read_only(&mut self) { self.writable = false; }

    /// Give the medium back, so a test can mount the same image again.
    /// # C: O(1)
    pub fn into_source(self) -> S { self.source }

    /// Read bytes at a byte offset on the medium.
    ///
    /// Every read is expressed in sectors because that is what the medium
    /// takes, so a request that does not begin on one is widened and the
    /// wanted bytes taken out of what comes back.
    /// # C: O(len)
    pub(crate) fn read_bytes(&self, offset: u64, buf: &mut [u8]) -> Result<(), Errno> {
        let unit = u64::from(self.geo.sector_size);
        let first = offset / unit;
        let skew = usize::try_from(offset % unit).map_err(|_| Errno::Eio)?;
        let span = (skew + buf.len()).next_multiple_of(unit as usize);
        let mut scratch = vec![0u8; span];
        self.source.read_sectors(first, &mut scratch)?;
        buf.copy_from_slice(&scratch[skew..skew + buf.len()]);
        Ok(())
    }

    /// Write bytes at a byte offset, reading back whatever a partial sector
    /// would otherwise lose. # C: O(len)
    pub(crate) fn write_bytes(&self, offset: u64, buf: &[u8]) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let unit = u64::from(self.geo.sector_size);
        let first = offset / unit;
        let skew = usize::try_from(offset % unit).map_err(|_| Errno::Eio)?;
        let span = (skew + buf.len()).next_multiple_of(unit as usize);
        let mut scratch = vec![0u8; span];
        // A write covering whole sectors does not need what was there;
        // anything narrower does, or the bytes either side are lost.
        if skew != 0 || span != buf.len() { self.source.read_sectors(first, &mut scratch)?; }
        scratch[skew..skew + buf.len()].copy_from_slice(buf);
        self.source.write_sectors(first, &scratch)
    }
}

#[cfg(test)]
#[path = "tests/volume.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/write.rs"]
mod write_tests;
