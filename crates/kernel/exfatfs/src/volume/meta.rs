//! The boot region, the volume flags, the label, and what `statfs` reports.
//!
//! Two bytes of the boot sector change while a volume is mounted — the flags
//! word and the in-use percentage — and NEITHER contributes to the boot
//! region's checksum. That is what makes marking a volume dirty a one-sector
//! write rather than a rewrite of twelve sectors and their checksum.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::boot;
use crate::checksum;
use crate::uapi::*;

use super::Volume;

/// What a mounted volume reports about its space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SpaceInfo {
    pub cluster_bytes: u64,
    /// Data clusters, which excludes the two reserved ones.
    pub total: u64,
    pub free: u64,
    pub name_max: u64,
}

impl<S: SectorSource> Volume<S> {
    /// What `statfs` answers. # C: O(1)
    pub fn space(&self) -> SpaceInfo {
        SpaceInfo {
            cluster_bytes: self.geo.cluster_bytes(),
            total: u64::from(self.geo.data_clusters()),
            free: u64::from(self.free_clusters()),
            name_max: crate::opts::EXFAT_NAME_MAX,
        }
    }

    /// Mark the volume dirty, or clean.
    ///
    /// The persistent flags this mount did not set are carried forward: a
    /// medium-failure bit cleared by a mount that repaired nothing tells the
    /// next reader the medium is sound when nobody has checked.
    /// # C: O(1 sector)
    pub fn set_dirty(&mut self, dirty: bool) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let flags = boot::flags_with_dirty(self.boot.vol_flags, dirty);
        if flags == self.boot.vol_flags { return Ok(()); }
        self.boot.vol_flags = flags;
        boot::set_vol_flags(&mut self.boot_bytes, flags);
        self.source.write_sectors(0, &self.boot_bytes)
    }

    /// Record how much of the volume is in use.
    ///
    /// Written at unmount rather than at every allocation: the byte is a hint
    /// for a user interface, and a sector write per allocated cluster would
    /// cost more than the hint is worth.
    /// # C: O(1 sector)
    pub fn flush_percent_in_use(&mut self) -> Result<(), Errno> {
        if !self.writable { return Ok(()); }
        let percent = boot::percent_in_use(u64::from(self.used_clusters),
                                           u64::from(self.geo.data_clusters()));
        if percent == self.boot.percent_in_use { return Ok(()); }
        self.boot.percent_in_use = percent;
        boot::set_percent_in_use(&mut self.boot_bytes, percent);
        self.source.write_sectors(0, &self.boot_bytes)
    }

    /// Whether the boot region's twelve sectors sum to the checksum they
    /// carry.
    ///
    /// A failure is reported rather than refused: the reference warns about a
    /// bad extended-boot signature and refuses only a bad checksum, and a
    /// caller that wants either behaviour can have it from this answer.
    /// # C: O(boot region bytes)
    pub fn verify_boot_region(&self) -> Result<bool, Errno> {
        let per = self.geo.sector_size as usize;
        let mut sum = 0u32;
        let mut buf = alloc::vec![0u8; per];
        for sector in 0..BOOT_REGION_SECTORS {
            self.source.read_sectors(sector, &mut buf)?;
            sum = checksum::boot_region(&buf, sum, sector == 0);
        }
        self.source.read_sectors(BOOT_CHECKSUM_SECTOR, &mut buf)?;
        // Every word of the checksum sector holds the same value, and all of
        // them must: a sector where only the first word matches is one another
        // implementation wrote wrongly.
        Ok(buf.chunks_exact(4)
            .all(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == sum))
    }

    /// Recompute the boot region's checksum sector.
    ///
    /// Needed only by something that changed a byte the checksum covers, which
    /// nothing in normal operation does — the two mutable bytes are excluded.
    /// # C: O(boot region bytes)
    pub fn rewrite_boot_checksum(&mut self) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let per = self.geo.sector_size as usize;
        let mut sum = 0u32;
        let mut buf = alloc::vec![0u8; per];
        for sector in 0..BOOT_REGION_SECTORS {
            self.source.read_sectors(sector, &mut buf)?;
            sum = checksum::boot_region(&buf, sum, sector == 0);
        }
        let word = sum.to_le_bytes();
        for chunk in buf.chunks_exact_mut(4) { chunk.copy_from_slice(&word); }
        self.source.write_sectors(BOOT_CHECKSUM_SECTOR, &buf)
    }

    /// The volume's label as a string. # C: O(label length)
    pub fn label_string(&self) -> alloc::string::String {
        self.label.as_ref().map(|l| l.as_string()).unwrap_or_default()
    }

    /// Set the volume's label.
    ///
    /// The label lives in the ROOT directory as an entry of its own, so
    /// setting it either rewrites the entry that is there or places a new one.
    /// # C: O(root bytes)
    pub fn set_label(&mut self, label: &str) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let units: alloc::vec::Vec<u16> = label.encode_utf16().collect();
        if units.len() > VOLUME_LABEL_LEN { return Err(Errno::Einval); }
        let mut bytes = alloc::vec![0u8; DENTRY_BYTES];
        crate::dirent::meta::write_label(&units, &mut bytes)?;
        let root = self.root;
        let existing = self.chain_bytes(&root)?;
        let at = existing.chunks_exact(DENTRY_BYTES).position(|r| r[0] == TYPE_VOLUME);
        let offset = match at {
            Some(index) => (index * DENTRY_BYTES) as u64,
            None => {
                let (offset, grown) = self.place_set(&super::DirHandle::Root, 1)?;
                self.root = grown;
                offset
            }
        };
        let root = self.root;
        self.write_at(&root, offset, &bytes)?;
        self.label = crate::dirent::meta::parse_label(&bytes);
        Ok(())
    }
}
