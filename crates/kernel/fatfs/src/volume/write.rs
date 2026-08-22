//! Changing a file's bytes, its length and its record.
//!
//! The order every path here uses is chosen so the states an interrupted write
//! can leave are ones a checker can repair: clusters are claimed and the table
//! written BEFORE any of the caller's bytes land in them, and the directory
//! record — which is what makes those bytes part of the file — is written
//! LAST. A file therefore never points at clusters the table calls free; the
//! reverse, clusters marked in use that no file claims, is what `fsck` calls a
//! lost chain and reclaims.
//!
//! This is ORDERING, not durability. Nothing here forces the device's own
//! cache, so a medium pulled mid-write can still have reordered what reached
//! it. The reference makes the same trade: FAT has no journal.

use alloc::vec;

use syscall::errno::Errno;

use crate::cluster_alloc::{alloc_clusters, chain_add, count_free, count_free_clusters,
                           free_chain_state, truncate_chain_state};
use crate::dirent::{Record, ENTRY_BYTES};
use crate::fatcache::{get_cluster, ChainCache, Seek, TO_EOF};
use crate::fsinfo;
use crate::time::FatTime;

use super::{chain_errno, DirEntry, SectorSource, Volume};

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

    /// Data clusters this volume has. # C: O(1)
    pub fn total_clusters(&self) -> u32 { self.geo.total_clusters }

    /// Free clusters, by scanning the table every time. # C: O(clusters)
    pub fn free_clusters(&self) -> u32 { count_free(&self.geo, &self.table) }

    /// Free clusters, scanning only the first time the answer is needed.
    ///
    /// This is the one `statfs` asks: a freshly mounted volume pays a scan
    /// once and every later question is free, which is the difference between
    /// a `df` that costs a table walk and one that does not.
    /// # C: O(clusters) on the first call, O(1) after
    pub fn free_clusters_counted(&mut self) -> u32 {
        count_free_clusters(&self.geo, &self.table, &mut self.free)
    }

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
    pub(crate) fn write_cluster(&self, cluster: u32, buf: &[u8]) -> Result<(), Errno> {
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

    /// Write the free count and the allocation hint back to the information
    /// sector, when this volume has one and they have moved.
    ///
    /// A sector whose signatures do not match is left alone: whatever occupies
    /// it belongs to something else, and the counters are a hint the next
    /// mount can do without.
    /// # C: O(1 sector)
    pub fn flush_fsinfo(&mut self) -> Result<(), Errno> {
        let Some(sector) = self.fsinfo_sector else { return Ok(()) };
        if !self.free.is_dirty() { return Ok(()); }
        let mut buf = vec![0u8; self.geo.sector_size as usize];
        self.source.read_sectors(u64::from(sector), &mut buf)?;
        if fsinfo::write_back(&mut buf, self.free.free_clusters(), Some(self.free.hint())) {
            self.source.write_sectors(u64::from(sector), &buf)?;
        }
        self.free.clear_dirty();
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

    /// The bytes of one directory record, as they stand. # C: O(cluster bytes)
    pub(crate) fn read_dir_record(&self, dir: Option<u32>, slot: u64)
        -> Result<[u8; ENTRY_BYTES], Errno> {
        let bytes = self.directory_bytes(dir)?;
        let at = usize::try_from(slot).map_err(|_| Errno::Eio)?;
        let end = at.checked_add(ENTRY_BYTES).ok_or(Errno::Eio)?;
        if end > bytes.len() { return Err(Errno::Eio); }
        let mut out = [0u8; ENTRY_BYTES];
        out.copy_from_slice(&bytes[at..end]);
        Ok(out)
    }

    /// Rewrite one directory record in place.
    ///
    /// The record is written back where it was read from, which is what the
    /// slot carried on every entry is for.
    /// # C: O(cluster bytes)
    pub(crate) fn write_dir_record(&self, dir: Option<u32>, slot: u64, record: &[u8; ENTRY_BYTES])
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
                let clusters = crate::chain::walk(&self.geo, &self.table, first).map_err(chain_errno)?;
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

    /// Rewrite one record's first cluster, size and modification time without
    /// touching the six bytes those fields do not cover.
    ///
    /// The record is READ before it is written. The alternative — rebuilding
    /// it from the four fields a short entry carries — sets the case bits and
    /// all three timestamps to zero, so every write to a file would report it
    /// as created at the start of 1980 under an all-uppercase name.
    /// # C: O(cluster bytes)
    pub(crate) fn stamp_record(&self, dir: Option<u32>, slot: u64, cluster: u32, size: u32,
                               now: FatTime) -> Result<(), Errno> {
        let raw = self.read_dir_record(dir, slot)?;
        let mut record = Record::parse(&raw).ok_or(Errno::Eio)?;
        record.short.cluster = cluster;
        record.short.size = size;
        record.times.modify = FatTime { time: now.time, date: now.date, cs: 0 };
        // Access is a DATE, and only the long-name type keeps one at all.
        if self.opts.long_names { record.times.access_date = now.date; }
        self.write_dir_record(dir, slot, &record.encode())
    }

    /// Write `data` at `offset` in the file `hit` names, extending its chain
    /// as needed and updating its directory record. Returns the new size.
    /// # C: O(bytes written)
    pub fn write_file_cached(&mut self, dir: Option<u32>, hit: &DirEntry, cache: &mut ChainCache,
                             offset: u64, data: &[u8], now: FatTime) -> Result<u64, Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        if hit.entry.is_dir() { return Err(Errno::Eisdir); }
        if data.is_empty() { return Ok(u64::from(hit.entry.size)); }
        let per = self.geo.cluster_bytes();
        let end = offset.checked_add(data.len() as u64).ok_or(Errno::Einval)?;
        let need = usize::try_from(end.div_ceil(per)).map_err(|_| Errno::Einval)?;

        let first = self.extend_chain(hit.entry.cluster, cache, need)?;

        let mut done = 0usize;
        let mut scratch = vec![0u8; usize::try_from(per).map_err(|_| Errno::Einval)?];
        while done < data.len() {
            let pos = offset + done as u64;
            let index = u32::try_from(pos / per).map_err(|_| Errno::Eio)?;
            let within = usize::try_from(pos % per).map_err(|_| Errno::Eio)?;
            let Seek::At { dclus, .. } = get_cluster(&self.geo, &self.table, cache, first, index)?
                else { return Err(Errno::Eio) };
            let take = core::cmp::min(usize::try_from(per).map_err(|_| Errno::Eio)? - within,
                                      data.len() - done);
            // A partial cluster is read before it is written, so the bytes
            // this write does not cover keep their old contents.
            if take < scratch.len() { self.read_cluster(dclus, &mut scratch)?; }
            scratch[within..within + take].copy_from_slice(&data[done..done + take]);
            self.write_cluster(dclus, &scratch)?;
            done += take;
        }

        let size = core::cmp::max(u64::from(hit.entry.size), end);
        self.stamp_record(dir, hit.slot, first,
                          u32::try_from(size).map_err(|_| Errno::Efbig)?, now)?;
        Ok(size)
    }

    /// Write without a remembered position. # C: O(chain length + bytes)
    pub fn write_file(&mut self, dir: Option<u32>, hit: &DirEntry, offset: u64, data: &[u8],
                      now: FatTime) -> Result<u64, Errno> {
        let mut cache = ChainCache::new();
        self.write_file_cached(dir, hit, &mut cache, offset, data, now)
    }

    /// Allocate the clusters covering a range without changing the visible
    /// file size or clearing the newly allocated bytes.  This is FAT's
    /// `FALLOC_FL_KEEP_SIZE` operation; the normal write path can subsequently
    /// consume the reserved chain without allocating it again.
    pub fn preallocate_file_cached(&mut self, dir: Option<u32>, hit: &DirEntry,
                                   cache: &mut ChainCache, offset: u64, len: u64,
                                   now: FatTime) -> Result<u32, Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        if hit.entry.is_dir() { return Err(Errno::Eisdir); }
        let end = offset.checked_add(len).ok_or(Errno::Einval)?;
        let per = self.geo.cluster_bytes();
        let need = usize::try_from(end.div_ceil(per)).map_err(|_| Errno::Efbig)?;
        let first = self.extend_chain(hit.entry.cluster, cache, need)?;
        if first != hit.entry.cluster {
            self.stamp_record(dir, hit.slot, first, hit.entry.size, now)?;
        }
        Ok(first)
    }

    /// Make the chain starting at `first` at least `need` clusters long, and
    /// report its first cluster — which a file that had none acquires here.
    ///
    /// The table reaches the medium before any byte does, so a half-written
    /// file never claims a cluster the table calls free.
    /// # C: O(clusters scanned)
    pub(crate) fn extend_chain(&mut self, first: u32, cache: &mut ChainCache, need: usize)
        -> Result<u32, Errno> {
        let (have, tail) = if first == 0 {
            (0usize, None)
        } else {
            match get_cluster(&self.geo, &self.table, cache, first, TO_EOF)? {
                Seek::Eof { fclus, dclus } => (fclus as usize + 1, Some(dclus)),
                Seek::At { fclus, dclus } => (fclus as usize + 1, Some(dclus)),
            }
        };
        if have >= need { return Ok(first); }
        let got = alloc_clusters(&self.geo, &mut self.table, &mut self.free, need - have)?;
        if let Some(tail) = tail {
            chain_add(&self.geo, &mut self.table, &mut self.free, &got, tail)?;
        }
        // Every remembered position for this file describes a chain that has
        // just changed length; keeping them risks handing back a cluster the
        // file no longer ends at.
        cache.invalidate();
        self.flush_table()?;
        self.flush_fsinfo()?;
        Ok(if first == 0 { got[0] } else { first })
    }

    /// Set a file's length to `len`, releasing or claiming whatever clusters
    /// that takes.
    ///
    /// GROWING allocates and zeroes. FAT stores no hole and no per-block
    /// allocation state, so a size covering clusters the file does not own
    /// reads whatever the medium last held there — this filesystem has no
    /// sparse files, and the reference expands by writing the gap out.
    ///
    /// SHRINKING writes the table before the record, so a file never keeps a
    /// size covering clusters the table has already released.
    /// # C: O(chain length + bytes zeroed)
    pub fn truncate_file_cached(&mut self, dir: Option<u32>, hit: &DirEntry,
                                cache: &mut ChainCache, len: u64, now: FatTime)
                                -> Result<(), Errno> {
        if !self.writable() { return Err(Errno::Erofs); }
        if hit.entry.is_dir() { return Err(Errno::Eisdir); }
        let old = u64::from(hit.entry.size);
        let per = self.geo.cluster_bytes();
        let keep = usize::try_from(len.div_ceil(per)).map_err(|_| Errno::Einval)?;
        let mut first = hit.entry.cluster;
        if len > old {
            first = self.extend_chain(first, cache, keep)?;
            self.fill_zeros(first, cache, old, len)?;
        } else if first != 0 {
            if keep == 0 {
                free_chain_state(&self.geo, &mut self.table, &mut self.free, first)?;
                first = 0;
            } else {
                truncate_chain_state(&self.geo, &mut self.table, &mut self.free, first, keep)?;
            }
            cache.invalidate();
            self.flush_table()?;
            self.flush_fsinfo()?;
        }
        self.stamp_record(dir, hit.slot, first,
                          u32::try_from(len).map_err(|_| Errno::Efbig)?, now)
    }

    /// Truncate without a remembered position. # C: O(chain length)
    pub fn truncate_file(&mut self, dir: Option<u32>, hit: &DirEntry, len: u64, now: FatTime)
        -> Result<(), Errno> {
        let mut cache = ChainCache::new();
        self.truncate_file_cached(dir, hit, &mut cache, len, now)
    }

    /// Clear the bytes of `[from, to)` in the chain starting at `first`.
    /// # C: O(bytes cleared)
    fn fill_zeros(&mut self, first: u32, cache: &mut ChainCache, from: u64, to: u64)
        -> Result<(), Errno> {
        if first == 0 || from >= to { return Ok(()); }
        let per = self.geo.cluster_bytes();
        let width = usize::try_from(per).map_err(|_| Errno::Einval)?;
        let mut scratch = vec![0u8; width];
        let mut pos = from;
        while pos < to {
            let index = u32::try_from(pos / per).map_err(|_| Errno::Eio)?;
            let within = usize::try_from(pos % per).map_err(|_| Errno::Eio)?;
            let take = core::cmp::min(width - within, usize::try_from(to - pos).unwrap_or(width));
            let Seek::At { dclus, .. } = get_cluster(&self.geo, &self.table, cache, first, index)?
                else { return Err(Errno::Eio) };
            if take < width {
                self.read_cluster(dclus, &mut scratch)?;
                for byte in scratch[within..within + take].iter_mut() { *byte = 0; }
            } else {
                for byte in scratch.iter_mut() { *byte = 0; }
            }
            self.write_cluster(dclus, &scratch)?;
            pos += take as u64;
        }
        Ok(())
    }
}
