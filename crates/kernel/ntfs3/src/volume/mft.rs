//! Reading and writing MFT records.
//!
//! A record is reached THROUGH the MFT's own runlist, not at a fixed offset:
//! the table is a file and can be fragmented like any other. The first record
//! is the exception, and only during mount, because the runlist that would
//! locate it is inside it.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::attrib::{self, Attribute};
use crate::record::{self, RecordHeader};
use crate::uapi::*;

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Byte offset on the medium of MFT record `number`.
    ///
    /// Through the runlist, so a fragmented MFT reads correctly; a record in a
    /// HOLE of the MFT is a volume whose table claims records it never
    /// allocated.
    /// # C: O(runs)
    pub(crate) fn record_offset(&self, number: u64) -> Result<u64, Errno> {
        let byte = number << self.geo.record_bits;
        let vcn = byte >> self.geo.cluster_bits;
        let within = byte & (u64::from(self.geo.cluster_size) - 1);
        // Before the runlist is known — during mount — the table is taken to
        // begin where the boot sector says and to be contiguous from there.
        if self.mft_runs.runs.is_empty() { return Ok(self.geo.mft_offset + byte); }
        let lcn = self.mft_runs.lookup(vcn).ok_or(Errno::Eio)?;
        if lcn == SPARSE_LCN { return Err(Errno::Eio); }
        Ok((lcn << self.geo.cluster_bits) + within)
    }

    /// Read one record, undo its update sequence, and decode its attributes.
    /// # C: O(record bytes)
    pub fn read_record(&self, number: u64) -> Result<(Vec<u8>, Vec<Attribute>), Errno> {
        let (bytes, header) = self.read_record_raw(number)?;
        let attrs = self.expand_attribute_list(number, &bytes,
                                               attrib::parse_all(&bytes, &header))?;
        Ok((bytes, attrs))
    }

    /// Add attributes named by the base record's `$ATTRIBUTE_LIST`.
    /// # C: O(list entries * record bytes)
    fn expand_attribute_list(&self, number: u64, bytes: &[u8], mut attrs: Vec<Attribute>)
        -> Result<Vec<Attribute>, Errno> {
        let Some(list) = attrs.iter().find(|a| a.ty == ATTR_LIST && a.is_first_segment())
            .cloned() else { return Ok(attrs) };
        let raw = self.attribute_bytes(bytes, &attrs, &list)?;
        for entry in attrib::list_entries(&raw)? {
            if entry.record == number { continue; }
            let (ext_bytes, ext_header) = self.read_record_raw(entry.record)?;
            if !ext_header.in_use() || ext_header.sequence != entry.sequence {
                return Err(Errno::Eio);
            }
            let ext_attrs = attrib::parse_all(&ext_bytes, &ext_header);
            let found = ext_attrs.into_iter().find(|a| a.ty == entry.ty
                && a.name == entry.name && a.id == entry.id
                && match a.body {
                    crate::attrib::Body::NonResident { svcn, .. } => svcn == entry.vcn,
                    crate::attrib::Body::Resident { .. } => entry.vcn == 0,
                }).ok_or(Errno::Eio)?;
            attrs.push(found);
        }
        Ok(attrs)
    }

    /// Read one record and its header, without decoding attributes.
    /// # C: O(record bytes)
    pub fn read_record_raw(&self, number: u64) -> Result<(Vec<u8>, RecordHeader), Errno> {
        if number >= self.mft_records { return Err(Errno::Enoent); }
        let offset = self.record_offset(number)?;
        let mut bytes = vec![0u8; self.geo.record_size as usize];
        self.read_bytes(offset, &mut bytes)?;
        crate::fixup::post_read(&mut bytes, false).map_err(|e| e.errno())?;
        let header = record::parse(&bytes).map_err(|e| e.errno())?;
        Ok((bytes, header))
    }

    /// Read one record only if it is live.
    ///
    /// A record whose in-use flag is clear is one a deletion left behind: its
    /// bytes are still a plausible record and reading it as a file resurrects
    /// something nothing names.
    /// # C: O(record bytes)
    pub fn read_live_record(&self, number: u64) -> Result<(Vec<u8>, Vec<Attribute>), Errno> {
        let (bytes, header) = self.read_record_raw(number)?;
        if !header.in_use() { return Err(Errno::Enoent); }
        let attrs = self.expand_attribute_list(number, &bytes,
                                               attrib::parse_all(&bytes, &header))?;
        Ok((bytes, attrs))
    }

    /// Write one record back, stamping a fresh update sequence.
    ///
    /// The sequence is ADVANCED, not reused: two writes carrying the same
    /// value make a tear between them undetectable, which is the one thing the
    /// sequence exists to catch.
    /// # C: O(record bytes)
    pub fn write_record(&self, number: u64, bytes: &mut [u8]) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let offset = self.record_offset(number)?;
        let current = u16::from_le_bytes([bytes[REC_OFF_FIX_OFF], bytes[REC_OFF_FIX_OFF + 1]]);
        let sample_at = usize::from(current);
        let sample = u16::from_le_bytes([bytes[sample_at], bytes[sample_at + 1]]);
        let next = crate::fixup::next_sample(sample);
        // The bytes are fixed up in place and put back afterwards, so the
        // caller's copy stays the record's real contents rather than one with
        // the sequence stamped through it.
        crate::fixup::pre_write(bytes, next).map_err(|e| e.errno())?;
        let result = self.write_bytes(offset, bytes);
        let _ = crate::fixup::post_read(bytes, false);
        result
    }

    /// Refresh the records `$MFTMirr` covers from the primary MFT.
    ///
    /// Linux performs this at filesystem sync/teardown. The mirror receives
    /// the same fixed-up bytes and update-sequence value as the primary copy;
    /// it is not a second logical record with an independently advanced
    /// sequence. # C: O(mirrored records * record bytes)
    pub(crate) fn update_mft_mirror(&self) -> Result<(), Errno> {
        if !self.writable { return Ok(()); }
        for number in 0..MFT_REC_USER.min(self.mft_records) {
            if self.read_mirror_record(number)?.is_none() { break; }
            let (mut bytes, _) = self.read_record_raw(number)?;
            let fix = usize::from(u16::from_le_bytes([
                bytes[REC_OFF_FIX_OFF], bytes[REC_OFF_FIX_OFF + 1],
            ]));
            let sample = u16::from_le_bytes([bytes[fix], bytes[fix + 1]]);
            crate::fixup::pre_write(&mut bytes, sample).map_err(|e| e.errno())?;
            let offset = self.geo.mft_mirror_offset + (number << self.geo.record_bits);
            if offset >= self.geo.sectors_per_volume * u64::from(self.geo.sector_size) { break; }
            self.write_bytes(offset, &bytes)?;
        }
        Ok(())
    }

    /// The mirror's copy of a record, when the mirror covers it.
    ///
    /// `$MFTMirr` holds only the first few records — the ones without which
    /// the volume cannot be mounted at all — so a request past its extent is
    /// not an error, it is a record the mirror does not carry.
    /// # C: O(record bytes)
    pub fn read_mirror_record(&self, number: u64) -> Result<Option<Vec<u8>>, Errno> {
        let offset = self.geo.mft_mirror_offset + (number << self.geo.record_bits);
        if offset >= self.geo.sectors_per_volume * u64::from(self.geo.sector_size) {
            return Ok(None);
        }
        let mut bytes = vec![0u8; self.geo.record_size as usize];
        self.read_bytes(offset, &mut bytes)?;
        if &bytes[REC_OFF_SIGN..REC_OFF_SIGN + 4] != SIG_FILE.as_slice() { return Ok(None); }
        crate::fixup::post_read(&mut bytes, false).map_err(|e| e.errno())?;
        Ok(Some(bytes))
    }

    /// Whether a record number is one the MFT's bitmap says is in use.
    /// # C: O(1)
    pub fn record_in_use(&self, number: u64) -> bool { self.mft_bitmap.is_set(number) }
}
