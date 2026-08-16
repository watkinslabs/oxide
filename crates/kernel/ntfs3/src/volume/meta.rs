//! The volume's own flags and label, and what `statfs` reports.

use alloc::string::String;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::attrib;
use crate::uapi::*;

use super::Volume;

/// What a mounted volume reports about its space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SpaceInfo {
    pub cluster_bytes: u64,
    pub total: u64,
    pub free: u64,
    /// Records the MFT holds, and how many are free.
    pub records: u64,
    pub records_free: u64,
    pub name_max: u64,
}

impl<S: SectorSource> Volume<S> {
    /// What `statfs` answers.
    ///
    /// The inode count is real here, unlike on FAT and exFAT: the MFT has a
    /// record count and a bitmap saying how many are used.
    /// # C: O(bitmap bits)
    pub fn space(&self) -> SpaceInfo {
        let used = self.mft_bitmap.used();
        SpaceInfo {
            cluster_bytes: u64::from(self.geo.cluster_size),
            total: self.geo.clusters,
            free: self.free_clusters(),
            records: self.mft_records,
            records_free: self.mft_records.saturating_sub(used),
            name_max: NTFS_NAME_LEN as u64,
        }
    }

    /// The volume's label. # C: O(label length)
    pub fn label(&self) -> String { crate::name::decode(&self.label) }

    /// The version the volume was formatted at. # C: O(1)
    pub fn version(&self) -> (u8, u8) { self.version }

    /// Mark the volume dirty, or clean.
    ///
    /// The other flags are carried forward: clearing a resize-log flag this
    /// mount did not act on tells the next reader something nobody checked.
    /// # C: O(record bytes)
    pub fn set_dirty(&mut self, dirty: bool) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let flags = if dirty { self.volume_flags | VOLUME_FLAG_DIRTY }
                    else { self.volume_flags & !VOLUME_FLAG_DIRTY };
        if flags == self.volume_flags { return Ok(()); }
        let (bytes, attrs) = self.read_record(MFT_REC_VOL)?;
        let attr = attrib::find(&attrs, ATTR_VOL_INFO, &[]).ok_or(Errno::Eio)?;
        let (start, end) = attr.resident_span().ok_or(Errno::Eio)?;
        if end > bytes.len() || end - start < SIZEOF_VOLUME_INFO { return Err(Errno::Eio); }
        let mut record = bytes;
        let at = start + VOLINFO_OFF_FLAGS;
        record[at..at + 2].copy_from_slice(&flags.to_le_bytes());
        self.write_record(MFT_REC_VOL, &mut record)?;
        self.volume_flags = flags;
        Ok(())
    }

    /// Whether the MFT and its mirror agree about the records the mirror
    /// covers.
    ///
    /// The mirror exists so a volume whose first records were lost can still
    /// be mounted; a disagreement means one of the two was written and the
    /// other was not, which is what a check repairs.
    /// # C: O(mirrored records)
    pub fn mirror_agrees(&self) -> Result<bool, Errno> {
        for number in 0..MFT_REC_USER.min(self.mft_records) {
            let Some(mirror) = self.read_mirror_record(number)? else { return Ok(true) };
            let Ok((primary, _)) = self.read_record_raw(number) else { return Ok(false) };
            // The update sequence differs between two copies of one record by
            // design, so the comparison is over what the record SAYS rather
            // than over its bytes.
            let a = crate::record::parse(&primary).map_err(|e| e.errno())?;
            let b = crate::record::parse(&mirror).map_err(|e| e.errno())?;
            if a.sequence != b.sequence || a.used != b.used || a.flags != b.flags {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
