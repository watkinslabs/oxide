//! An attribute's bytes: resident, non-resident, sparse and compressed.
//!
//! Four cases, and getting any of them wrong reads plausible nonsense:
//!
//! - **Resident** — the data is inside the record.
//! - **Non-resident** — the record holds a runlist naming clusters.
//! - **Sparse** — some of those runs are HOLES, and a hole reads as zeros
//!   rather than as cluster zero, which is the boot sector.
//! - **Compressed** — the runs are grouped into units of sixteen clusters, and
//!   a unit shorter than its full width is compressed, with the missing
//!   clusters a hole that is NOT a hole: it is the space the compression
//!   saved, and reading it as zeros returns zeros where the file has data.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::attrib::{Attribute, Body};
use crate::lznt;
use crate::run::{self, Runs};
use crate::uapi::*;

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Every run of one attribute, across all its segments.
    ///
    /// A file too fragmented for one record's runlist is split across several
    /// attributes of the same type and name; reading only the first gives the
    /// first part of the file and calls it the whole.
    /// # C: O(runs)
    pub fn attribute_runs(&self, bytes: &[u8], attrs: &[Attribute], attr: &Attribute)
        -> Result<Runs, Errno> {
        let mut runs = Runs::new();
        for seg in crate::attrib::segments(attrs, attr.ty, &attr.name) {
            let Body::NonResident { svcn, evcn, .. } = seg.body else { continue };
            let record = u64::from(u32::from_le_bytes([
                bytes[MFT_OFF_RECORD_NUM], bytes[MFT_OFF_RECORD_NUM + 1],
                bytes[MFT_OFF_RECORD_NUM + 2], bytes[MFT_OFF_RECORD_NUM + 3],
            ]));
            let owned;
            let source = if record == seg.record { bytes } else {
                owned = self.read_record_raw(seg.record)?.0;
                &owned
            };
            let (start, end) = seg.run_span().ok_or(Errno::Eio)?;
            if end > source.len() { return Err(Errno::Eio); }
            let part = run::unpack(&source[start..end], svcn, evcn, self.geo.clusters)
                .map_err(|e| e.errno())?;
            for r in part.runs { runs.push(r); }
        }
        Ok(runs)
    }

    /// The whole of an attribute's data. # C: O(attribute bytes)
    pub fn attribute_bytes(&self, bytes: &[u8], attrs: &[Attribute], attr: &Attribute)
        -> Result<Vec<u8>, Errno> {
        let len = usize::try_from(attr.data_size()).map_err(|_| Errno::Einval)?;
        let mut out = vec![0u8; len];
        let got = self.read_attribute(bytes, attrs, attr, 0, &mut out)?;
        out.truncate(got);
        Ok(out)
    }

    /// Read from an attribute, returning how many bytes were read.
    /// # C: O(bytes read)
    pub fn read_attribute(&self, bytes: &[u8], attrs: &[Attribute], attr: &Attribute,
                          offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        // Nothing here can read an encrypted attribute, and returning its
        // ciphertext as the file's contents would be worse than refusing.
        if attr.encrypted() { return Err(Errno::Eacces); }
        let size = attr.data_size();
        if offset >= size { return Ok(0); }
        let want = core::cmp::min(buf.len() as u64, size - offset) as usize;
        if want == 0 { return Ok(0); }

        let record = u64::from(u32::from_le_bytes([
            bytes[MFT_OFF_RECORD_NUM], bytes[MFT_OFF_RECORD_NUM + 1],
            bytes[MFT_OFF_RECORD_NUM + 2], bytes[MFT_OFF_RECORD_NUM + 3],
        ]));
        let owned;
        let source = if record == attr.record { bytes } else {
            owned = self.read_record_raw(attr.record)?.0;
            &owned
        };
        if let Some((start, end)) = attr.resident_span() {
            if end > source.len() { return Err(Errno::Eio); }
            let from = start + offset as usize;
            let take = core::cmp::min(want, end.saturating_sub(from));
            buf[..take].copy_from_slice(&source[from..from + take]);
            // Past the resident data but within the declared size is zeros:
            // the record cannot hold more than it holds.
            for b in buf[take..want].iter_mut() { *b = 0; }
            return Ok(want);
        }

        let runs = self.attribute_runs(bytes, attrs, attr)?;
        // Past the VALID size the attribute has never been written, whatever
        // its clusters hold — that is the previous owner's data.
        let valid = attr.valid_size();
        if let Some(unit) = attr.compression_unit() {
            self.read_compressed(&runs, unit, offset, &mut buf[..want], valid)?;
        } else {
            self.read_plain(&runs, offset, &mut buf[..want], valid)?;
        }
        Ok(want)
    }

    /// Read an uncompressed run of clusters, filling holes and the tail past
    /// the valid size with zeros. # C: O(bytes read)
    fn read_plain(&self, runs: &Runs, offset: u64, buf: &mut [u8], valid: u64)
        -> Result<(), Errno> {
        let per = u64::from(self.geo.cluster_size);
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let vcn = pos / per;
            let within = (pos % per) as usize;
            let take = core::cmp::min(per as usize - within, buf.len() - done);
            if pos >= valid {
                for b in buf[done..done + take].iter_mut() { *b = 0; }
                done += take;
                continue;
            }
            match runs.lookup(vcn) {
                None => return Err(Errno::Eio),
                Some(SPARSE_LCN) => { for b in buf[done..done + take].iter_mut() { *b = 0; } }
                Some(lcn) => {
                    let at = (lcn << self.geo.cluster_bits) + within as u64;
                    self.read_bytes(at, &mut buf[done..done + take])?;
                }
            }
            done += take;
        }
        Ok(())
    }

    /// Read a compressed attribute, one compression unit at a time.
    ///
    /// A unit whose runs cover its full width is stored plain; one whose runs
    /// are shorter is compressed into those clusters, with the rest of the
    /// unit a hole standing for the saved space. Deciding by the FILE's sparse
    /// flag instead reads a stored unit as compressed and produces nothing
    /// resembling the file.
    /// # C: O(bytes read + unit bytes)
    fn read_compressed(&self, runs: &Runs, unit: u32, offset: u64, buf: &mut [u8], valid: u64)
        -> Result<(), Errno> {
        let per = u64::from(self.geo.cluster_size);
        let unit_bytes = per * u64::from(unit);
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let unit_index = pos / unit_bytes;
            let within = (pos % unit_bytes) as usize;
            let take = core::cmp::min(unit_bytes as usize - within, buf.len() - done);
            if pos >= valid {
                for b in buf[done..done + take].iter_mut() { *b = 0; }
                done += take;
                continue;
            }
            let plain = self.read_unit(runs, unit, unit_index, unit_bytes)?;
            let from = core::cmp::min(within, plain.len());
            let stop = core::cmp::min(from + take, plain.len());
            buf[done..done + (stop - from)].copy_from_slice(&plain[from..stop]);
            for b in buf[done + (stop - from)..done + take].iter_mut() { *b = 0; }
            done += take;
        }
        Ok(())
    }

    /// One compression unit's uncompressed bytes. # C: O(unit bytes)
    fn read_unit(&self, runs: &Runs, unit: u32, index: u64, unit_bytes: u64)
        -> Result<Vec<u8>, Errno> {
        let per = u64::from(self.geo.cluster_size);
        let first_vcn = index * u64::from(unit);
        // How many of the unit's clusters are actually allocated decides
        // whether the unit is stored or compressed.
        let mut allocated = 0u32;
        for i in 0..unit {
            match runs.lookup(first_vcn + u64::from(i)) {
                Some(lcn) if lcn != SPARSE_LCN => allocated += 1,
                _ => break,
            }
        }
        if allocated == 0 {
            // The whole unit is a hole: a genuinely sparse region.
            return Ok(vec![0u8; unit_bytes as usize]);
        }
        let mut raw = vec![0u8; (u64::from(allocated) * per) as usize];
        for i in 0..allocated {
            let lcn = runs.lookup(first_vcn + u64::from(i)).ok_or(Errno::Eio)?;
            let at = lcn << self.geo.cluster_bits;
            let start = (u64::from(i) * per) as usize;
            self.read_bytes(at, &mut raw[start..start + per as usize])?;
        }
        if allocated == unit { return Ok(raw); }
        lznt::decompress(&raw, unit_bytes as usize).map_err(|e| e.errno())
    }

    /// Write into an uncompressed, non-sparse attribute's existing clusters.
    ///
    /// Growth, compression and holes are the caller's problem: this writes
    /// where the runs already point and refuses anything else, because a write
    /// that silently skipped a hole would lose the bytes it was given.
    /// # C: O(bytes written)
    pub(crate) fn write_runs(&self, runs: &Runs, offset: u64, buf: &[u8]) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let per = u64::from(self.geo.cluster_size);
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let vcn = pos / per;
            let within = (pos % per) as usize;
            let take = core::cmp::min(per as usize - within, buf.len() - done);
            let lcn = runs.lookup(vcn).ok_or(Errno::Eio)?;
            if lcn == SPARSE_LCN { return Err(Errno::Eio); }
            let at = (lcn << self.geo.cluster_bits) + within as u64;
            self.write_bytes(at, &buf[done..done + take])?;
            done += take;
        }
        Ok(())
    }
}
