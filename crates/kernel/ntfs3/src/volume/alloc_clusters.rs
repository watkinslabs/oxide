//! Claiming and releasing clusters, and MFT records.
//!
//! Two bitmaps, one rule: a bit is set on the medium before anything points at
//! what it covers, and cleared only after nothing does. The reverse order
//! leaves a cluster two files believe they own, which is the one corruption a
//! checker cannot repair without choosing which file to lose.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::attrib;
use crate::run::{Run, Runs};
use crate::uapi::*;

use super::Volume;

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
        let number = self.mft_bitmap.find_free(self.record_hint).ok_or(Errno::Enospc)?;
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
