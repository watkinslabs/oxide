//! The boot sector, and the geometry it resolves to.
//!
//! Two of its fields are signed, and the sign is the unit: a POSITIVE record
//! size counts clusters, a NEGATIVE one is a power-of-two byte count. Reading
//! either as unsigned gives a record size of 246 clusters where the volume
//! means 1024 bytes, and every MFT record after the first is then read from
//! the wrong place.

use syscall::errno::Errno;

use crate::uapi::*;

/// The fields the boot sector declares.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Boot {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub sectors_per_volume: u64,
    pub mft_cluster: u64,
    pub mft_mirror_cluster: u64,
    /// Signed: clusters when positive, a shift when negative.
    pub record_size_field: i8,
    pub index_size_field: i8,
    pub serial: u64,
}

/// The resolved layout of a mounted volume.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Geometry {
    pub sector_size: u32,
    pub sector_bits: u32,
    pub cluster_size: u32,
    pub cluster_bits: u32,
    /// Bytes of one MFT record.
    pub record_size: u32,
    pub record_bits: u32,
    /// Bytes of one index buffer.
    pub index_size: u32,
    pub sectors_per_volume: u64,
    pub clusters: u64,
    /// Byte offset of the first MFT record, and of its mirror.
    pub mft_offset: u64,
    pub mft_mirror_offset: u64,
    pub serial: u64,
}

/// Why a boot sector was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BootError {
    TooShort,
    /// The eight-byte identifier is not this filesystem's.
    NotNtfs,
    /// A sector size below 512 bytes or not a power of two.
    BadSectorSize,
    /// A cluster of no sectors, or not a power of two.
    BadClusterSize,
    /// The MFT begins outside the volume.
    MftOutOfVolume,
    /// A record size the format cannot express.
    BadRecordSize,
    /// An index size the format cannot express.
    BadIndexSize,
    /// A cluster narrower than a sector.
    ClusterBelowSector,
    /// More clusters than a 32-bit cluster number can name.
    TooManyClusters,
}

impl BootError {
    /// # C: O(1)
    pub fn errno(self) -> Errno {
        match self { BootError::TooShort => Errno::Eio, _ => Errno::Einval }
    }
}

/// Read one 64-bit field. # C: O(1)
fn le64(bytes: &[u8], at: usize) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(out)
}

/// Decode a boot sector. # C: O(1)
pub fn parse(bytes: &[u8]) -> Result<Boot, BootError> {
    if bytes.len() < BOOT_BYTES { return Err(BootError::TooShort); }
    if &bytes[BOOT_OFF_SYSTEM_ID..BOOT_OFF_SYSTEM_ID + 8] != SYSTEM_ID.as_slice() {
        return Err(BootError::NotNtfs);
    }
    // The sector-size field is NOT aligned, so it is read a byte at a time
    // rather than as a 16-bit word.
    let bytes_per_sector = (u32::from(bytes[BOOT_OFF_BYTES_PER_SECTOR + 1]) << 8)
        | u32::from(bytes[BOOT_OFF_BYTES_PER_SECTOR]);
    Ok(Boot {
        bytes_per_sector,
        sectors_per_cluster: sectors_per_cluster(bytes[BOOT_OFF_SECTORS_PER_CLUSTER]),
        sectors_per_volume: le64(bytes, BOOT_OFF_SECTORS_PER_VOLUME),
        mft_cluster: le64(bytes, BOOT_OFF_MFT_CLST),
        mft_mirror_cluster: le64(bytes, BOOT_OFF_MFT2_CLST),
        record_size_field: bytes[BOOT_OFF_RECORD_SIZE] as i8,
        index_size_field: bytes[BOOT_OFF_INDEX_SIZE] as i8,
        serial: le64(bytes, BOOT_OFF_SERIAL),
    })
}

/// Sectors in one cluster, from the byte that names them.
///
/// A value above 0x80 is a NEGATIVE shift, exactly like the two size fields:
/// that is how a volume names a cluster larger than 255 sectors. Reading it as
/// a plain count gives a cluster of 246 sectors where the volume means 1024.
/// # C: O(1)
pub fn sectors_per_cluster(field: u8) -> u32 {
    if field <= 0x80 { u32::from(field) } else { 1u32 << (256 - u32::from(field)) }
}

/// A size field's byte count, given the cluster size it may be counted in.
///
/// Positive counts CLUSTERS; negative is a power-of-two byte count. `limit`
/// bounds how far a negative shift may go.
/// # C: O(1)
pub fn sized_field(field: i8, cluster_bits: u32, limit: i8) -> Option<u32> {
    if field >= 0 { return (field as u32).checked_shl(cluster_bits); }
    if -field > limit { return None; }
    Some(1u32 << (-field) as u32)
}

/// Resolve a boot sector into a layout, refusing every combination the format
/// does not admit. # C: O(1)
pub fn resolve(boot: &Boot) -> Result<Geometry, BootError> {
    let sector_size = boot.bytes_per_sector;
    if sector_size < SECTOR_BYTES as u32 || !sector_size.is_power_of_two() {
        return Err(BootError::BadSectorSize);
    }
    let spc = boot.sectors_per_cluster;
    if spc == 0 || !spc.is_power_of_two() { return Err(BootError::BadClusterSize); }
    let cluster_size = sector_size.checked_mul(spc).ok_or(BootError::BadClusterSize)?;
    let cluster_bits = cluster_size.trailing_zeros();
    // A cluster narrower than a sector cannot address the medium at all.
    if cluster_size < sector_size { return Err(BootError::ClusterBelowSector); }

    let sectors = boot.sectors_per_volume;
    if boot.mft_cluster.saturating_mul(u64::from(spc)) >= sectors
        || boot.mft_mirror_cluster.saturating_mul(u64::from(spc)) >= sectors {
        return Err(BootError::MftOutOfVolume);
    }

    let record_size = sized_field(boot.record_size_field, cluster_bits, MAX_SHIFT_BYTES_PER_MFT)
        .ok_or(BootError::BadRecordSize)?;
    if record_size < SECTOR_BYTES as u32 || !record_size.is_power_of_two()
        || record_size > MAX_BYTES_PER_MFT {
        return Err(BootError::BadRecordSize);
    }
    let index_size = sized_field(boot.index_size_field, cluster_bits, MAX_SHIFT_BYTES_PER_INDEX)
        .ok_or(BootError::BadIndexSize)?;
    if index_size < SECTOR_BYTES as u32 || !index_size.is_power_of_two()
        || index_size > MAX_BYTES_PER_INDEX {
        return Err(BootError::BadIndexSize);
    }

    let volume_bytes = sectors.saturating_mul(u64::from(sector_size));
    let clusters = volume_bytes >> cluster_bits;
    // A cluster number is 32 bits on this format as every implementation
    // writes it; a volume needing more cannot be addressed.
    if clusters >> 32 != 0 { return Err(BootError::TooManyClusters); }

    Ok(Geometry {
        sector_size,
        sector_bits: sector_size.trailing_zeros(),
        cluster_size,
        cluster_bits,
        record_size,
        record_bits: record_size.trailing_zeros(),
        index_size,
        sectors_per_volume: sectors,
        clusters,
        mft_offset: boot.mft_cluster << cluster_bits,
        mft_mirror_offset: boot.mft_mirror_cluster << cluster_bits,
        serial: boot.serial,
    })
}

impl Geometry {
    /// Byte offset of one MFT record. # C: O(1)
    pub fn record_offset(&self, number: u64) -> u64 {
        self.mft_offset + (number << self.record_bits)
    }

    /// Byte offset of a cluster. # C: O(1)
    pub fn cluster_offset(&self, lcn: u64) -> u64 { lcn << self.cluster_bits }

    /// Clusters needed to hold `bytes`. # C: O(1)
    pub fn clusters_for(&self, bytes: u64) -> u64 { bytes.div_ceil(u64::from(self.cluster_size)) }

    /// The widest attribute one record can hold, once its header and fixup
    /// array are accounted for. # C: O(1)
    pub fn max_attr_bytes(&self) -> u32 {
        let header = (u32::from(MFT_FIXUP_OFFSET_SMALL)).next_multiple_of(8);
        let fixups = ((self.record_size >> SECTOR_SHIFT) * 2).next_multiple_of(8);
        self.record_size.saturating_sub(header).saturating_sub(fixups).saturating_sub(8)
    }
}

#[cfg(test)]
#[path = "tests/boot.rs"]
pub(crate) mod tests;
