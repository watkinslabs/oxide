//! Claiming and releasing clusters, and MFT records.
//!
//! Two bitmaps, one rule: a bit is set on the medium before anything points at
//! what it covers, and cleared only after nothing does. The reverse order
//! leaves a cluster two files believe they own, which is the one corruption a
//! checker cannot repair without choosing which file to lose.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::attrib;
use crate::run::{Run, Runs};
use crate::uapi::*;

use super::Volume;
use super::edit;

impl<S: SectorSource> Volume<S> {
    /// Clusters this volume has free. # C: O(1)
    pub fn free_clusters(&self) -> u64 {
        self.geo.clusters.saturating_sub(self.cluster_bitmap.used())
    }

    /// Clusters in use. # C: O(bitmap bits)
    pub fn used_clusters(&self) -> u64 { self.cluster_bitmap.used() }

    /// Write the byte range of `$Bitmap` holding a changed bit back to the
    /// medium. # C: O(sector bytes)
    fn flush_cluster_bit(&mut self, lcn: u64) -> Result<(), Errno> {
        let byte = lcn / 8;
        let unit = u64::from(self.geo.sector_size);
        let start = (byte / unit) * unit;
        let bytes = self.cluster_bitmap.bytes();
        let end = core::cmp::min(start + unit, bytes.len() as u64);
        let slice = bytes[start as usize..end as usize].to_vec();
        self.write_named_attribute(MFT_REC_BITMAP, ATTR_DATA, &[], start, &slice)
    }

    /// Claim a run of clusters. # C: O(count)
    pub(crate) fn claim_clusters(&mut self, lcn: u64, count: u64) -> Result<(), Errno> {
        self.cluster_bitmap.set_range(lcn, count)?;
        for i in 0..count { self.flush_cluster_bit(lcn + i)?; }
        Ok(())
    }

    /// Release a run of clusters. # C: O(count)
    pub(crate) fn release_clusters(&mut self, lcn: u64, count: u64) -> Result<(), Errno> {
        self.cluster_bitmap.clear_range(lcn, count)?;
        for i in 0..count { self.flush_cluster_bit(lcn + i)?; }
        Ok(())
    }

    /// Claim `count` clusters, as few runs as the volume allows.
    ///
    /// One extent is preferred and several are accepted: a file that cannot be
    /// laid down contiguously is normal, and refusing would make a fragmented
    /// volume unwritable rather than slow.
    /// # C: O(count * volume clusters) worst case
    pub fn alloc_clusters(&mut self, count: u64) -> Result<Runs, Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let mut out = Runs::new();
        if count == 0 { return Ok(out); }
        if count > self.free_clusters() { return Err(Errno::Enospc); }
        let mut want = count;
        let mut vcn = 0u64;
        // The largest run first, then whatever is left, so a file that fits
        // one extent gets one rather than a run per cluster.
        while want > 0 {
            let mut take = want;
            let found = loop {
                if take == 0 { break None; }
                match self.cluster_bitmap.find_free_run(self.cluster_hint, take) {
                    Some(lcn) => break Some((lcn, take)),
                    None => take /= 2,
                }
            };
            let Some((lcn, len)) = found else {
                // Nothing was claimed that is not in `out`; release it so a
                // failed allocation leaves no cluster nothing points at.
                for run in &out.runs { self.release_clusters(run.lcn, run.len)?; }
                return Err(Errno::Enospc);
            };
            self.claim_clusters(lcn, len)?;
            out.push(Run { vcn, lcn, len });
            vcn += len;
            want -= len;
            self.cluster_hint = lcn + len;
        }
        Ok(out)
    }

    /// Release every cluster a runlist names, holes excepted. # C: O(runs)
    pub fn free_runs(&mut self, runs: &Runs) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        for run in &runs.runs {
            if run.is_hole() { continue; }
            self.release_clusters(run.lcn, run.len)?;
        }
        Ok(())
    }

    /// Write the byte range of the MFT's `$BITMAP` holding a changed bit.
    /// # C: O(sector bytes)
    fn flush_record_bit(&mut self, number: u64) -> Result<(), Errno> {
        let byte = number / 8;
        let unit = u64::from(self.geo.sector_size);
        let start = (byte / unit) * unit;
        let bytes = self.mft_bitmap.bytes();
        let end = core::cmp::min(start + unit, bytes.len() as u64);
        if start >= end { return Ok(()); }
        let slice = bytes[start as usize..end as usize].to_vec();
        self.write_named_attribute(MFT_REC_MFT, ATTR_BITMAP, &[], start, &slice)
    }

    /// Where the next record allocation starts looking.
    ///
    /// A mount begins at the first record a user file may occupy and walks
    /// forward, wrapping once; resetting the hint is what makes a freed record
    /// reachable again without waiting for the wrap.
    /// # C: O(1)
    pub fn set_record_hint(&mut self, number: u64) { self.record_hint = number; }

    /// Claim a free MFT record and format it.
    ///
    /// The record's SEQUENCE advances rather than restarting, so a reference
    /// made to whatever used the record before does not resolve to the new
    /// file. Restarting it at one is how a stale reference silently names the
    /// wrong file.
    /// # C: O(records)
    pub fn alloc_record(&mut self) -> Result<(u64, u16), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let number = match self.mft_bitmap.find_free(self.record_hint) {
            Some(number) => number,
            None => {
                let next = self.mft_records.checked_add(1024).ok_or(Errno::Efbig)?;
                self.extend_mft(next)?;
                self.mft_bitmap.find_free(self.record_hint).ok_or(Errno::Enospc)?
            }
        };
        if number < MFT_REC_USER { return Err(Errno::Enospc); }
        let previous = self.read_record_raw(number).map(|(_, h)| h.sequence).unwrap_or(0);
        let sequence = crate::record::next_sequence(previous);
        self.mft_bitmap.set(number)?;
        self.flush_record_bit(number)?;
        self.record_hint = number + 1;
        let mut bytes = crate::record::format(self.geo.record_size, number, sequence);
        self.write_record(number, &mut bytes)?;
        Ok((number, sequence))
    }

    /// Extend `$MFT` and its record bitmap before handing out a new record.
    ///
    /// The table's data and bitmap are resized together: publishing a larger
    /// record count without the corresponding bitmap would make an allocator
    /// hand out records whose ownership cannot survive a remount. # C: O(MFT
    /// runlist + bitmap bytes + newly allocated clusters)
    fn extend_mft(&mut self, new_records: u64) -> Result<(), Errno> {
        let record_bytes = new_records.checked_shl(self.geo.record_bits).ok_or(Errno::Efbig)?;
        let new_clusters = self.geo.clusters_for(record_bytes);
        if new_clusters <= self.mft_runs.clusters() { return Err(Errno::Eio); }

        let extra = self.alloc_clusters(new_clusters - self.mft_runs.clusters())?;
        let base = self.mft_runs.clusters();
        let mut new_runs = self.mft_runs.clone();
        for mut run in extra.runs { run.vcn += base; new_runs.push(run); }

        let (mut mft_record, mft_attrs) = self.read_record(MFT_REC_MFT)?;
        let mft_data = attrib::find(&mft_attrs, ATTR_DATA, &[]).ok_or(Errno::Eio)?;
        if mft_data.record != MFT_REC_MFT { return Err(Errno::Eopnotsupp); }
        let replacement = crate::volume::edit::non_resident(
            ATTR_DATA, &[], mft_data.id, &new_runs,
            new_clusters << self.geo.cluster_bits, record_bytes, record_bytes,
            self.geo.cluster_bits);
        let mft_header = crate::record::parse(&mft_record).map_err(|e| e.errno())?;
        crate::volume::edit::replace_at(&mut mft_record, &mft_header,
                                        mft_data.offset, &replacement)?;
        self.write_record(MFT_REC_MFT, &mut mft_record)?;

        let bitmap_bytes = crate::bitmap::bytes_for(new_records) as usize;
        let mut bitmap = self.mft_bitmap.bytes().to_vec();
        let old_bits = self.mft_records;
        if old_bits % 8 != 0 && old_bits / 8 < bitmap.len() as u64 {
            bitmap[(old_bits / 8) as usize] &= (1u8 << (old_bits % 8)) - 1;
        }
        bitmap.resize(bitmap_bytes, 0);
        self.replace_mft_bitmap(bitmap, new_records)?;
        self.mft_runs = new_runs;
        self.mft_records = new_records;
        Ok(())
    }

    /// Resize `$MFT::$BITMAP`, converting it to non-resident storage when its
    /// record no longer has room for a resident value. # C: O(bitmap bytes)
    fn replace_mft_bitmap(&mut self, bitmap: Vec<u8>, new_records: u64) -> Result<(), Errno> {
        let (mut record, attrs) = self.read_record(MFT_REC_MFT)?;
        let old = attrib::find(&attrs, ATTR_BITMAP, &[]).ok_or(Errno::Eio)?;
        if old.record != MFT_REC_MFT { return Err(Errno::Eopnotsupp); }
        let header = crate::record::parse(&record).map_err(|e| e.errno())?;
        let resident = crate::volume::edit::resident(ATTR_BITMAP, &[], old.id, false, &bitmap);
        if !old.non_resident && resident.len() <= old.size as usize + edit::free_space(&record, &header) {
            edit::replace_at(&mut record, &header, old.offset, &resident)?;
            self.write_record(MFT_REC_MFT, &mut record)?;
            self.mft_bitmap = crate::bitmap::Bitmap::new(bitmap, new_records);
            return Ok(());
        }

        let mut runs = if old.non_resident {
            self.attribute_runs(&record, &attrs, old)?
        } else { Runs::new() };
        let need = self.geo.clusters_for(bitmap.len() as u64);
        if runs.clusters() < need {
            let extra = self.alloc_clusters(need - runs.clusters())?;
            let base = runs.clusters();
            for mut run in extra.runs { run.vcn += base; runs.push(run); }
        }
        self.write_runs(&runs, 0, &bitmap)?;
        let replacement = edit::non_resident(ATTR_BITMAP, &[], old.id, &runs,
                                              runs.clusters() << self.geo.cluster_bits,
                                              bitmap.len() as u64, bitmap.len() as u64,
                                              self.geo.cluster_bits);
        edit::replace_at(&mut record, &header, old.offset, &replacement)?;
        self.write_record(MFT_REC_MFT, &mut record)?;
        self.mft_bitmap = crate::bitmap::Bitmap::new(bitmap, new_records);
        Ok(())
    }

    /// Release an MFT record, clearing its in-use flag and its bit.
    ///
    /// The flag goes first: a record whose bit is clear but whose flag is set
    /// is one a scan still reads as a file, where the reverse is merely a
    /// record nothing will reuse until a check runs.
    /// # C: O(record bytes)
    pub fn free_record(&mut self, number: u64) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let (mut bytes, header) = self.read_record_raw(number)?;
        crate::record::set_flags(&mut bytes, header.flags & !RECORD_FLAG_IN_USE);
        self.write_record(number, &mut bytes)?;
        self.mft_bitmap.clear(number)?;
        self.flush_record_bit(number)
    }

    /// Write into an attribute of a record named by type and name.
    ///
    /// Used for the volume's own structures — the two bitmaps — whose
    /// attributes already have the clusters the write lands in.
    /// # C: O(bytes written)
    pub(crate) fn write_named_attribute(&mut self, number: u64, ty: u32, name: &[u16],
                                        offset: u64, buf: &[u8]) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let (bytes, attrs) = self.read_record(number)?;
        let attr = attrib::find(&attrs, ty, name).ok_or(Errno::Enoent)?;
        if let Some((start, _)) = attr.resident_span() {
            let mut record = bytes.clone();
            let at = start + offset as usize;
            if at + buf.len() > record.len() { return Err(Errno::Eio); }
            record[at..at + buf.len()].copy_from_slice(buf);
            return self.write_record(number, &mut record);
        }
        let runs = self.attribute_runs(&bytes, &attrs, attr)?;
        self.write_runs(&runs, offset, buf)
    }
}
