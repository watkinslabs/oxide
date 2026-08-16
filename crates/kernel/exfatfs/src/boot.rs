//! The boot sector, and what makes one an exFAT volume rather than a FAT one.
//!
//! The 53 bytes where FAT keeps its BIOS parameter block must be ZERO here.
//! That field is the whole guard against mounting a FAT volume as exFAT: the
//! signature and the name string can both be present on a medium that carries
//! a FAT filesystem underneath, and reading one as the other resolves a layout
//! that points at arbitrary sectors.

use syscall::errno::Errno;

use crate::uapi::*;

/// The fields the boot sector declares, before any of them are resolved
/// against each other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Boot {
    pub partition_offset: u64,
    pub vol_length: u64,
    pub fat_offset: u32,
    pub fat_length: u32,
    pub clu_offset: u32,
    pub clu_count: u32,
    pub root_cluster: u32,
    pub vol_serial: u32,
    pub fs_revision: [u8; 2],
    pub vol_flags: u16,
    pub sect_size_bits: u8,
    pub sect_per_clus_bits: u8,
    pub num_fats: u8,
    pub drv_sel: u8,
    pub percent_in_use: u8,
}

/// Why a boot sector was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BootError {
    /// Fewer bytes than a boot sector.
    TooShort,
    /// The last two bytes are not the signature.
    BadSignature,
    /// The eight-byte name is not this filesystem's.
    NotExfat,
    /// The field that must be zero is not — this is a FAT volume.
    FatVolume,
    /// Neither one table nor two.
    BadFatCount,
    /// A sector smaller than 512 bytes or larger than 4096.
    BadSectorSize,
    /// A cluster larger than the format admits.
    BadClusterSize,
    /// The table is too short to hold an entry per cluster.
    BadFatLength,
    /// The heap begins before the tables end.
    BadDataStart,
}

impl BootError {
    /// # C: O(1)
    pub fn errno(self) -> Errno {
        match self {
            // A medium too short to hold a boot sector is a truncated device,
            // not a volume with a bad field in it.
            BootError::TooShort => Errno::Eio,
            _ => Errno::Einval,
        }
    }
}

/// Read one 16-bit field. # C: O(1)
fn le16(bytes: &[u8], at: usize) -> u16 { u16::from_le_bytes([bytes[at], bytes[at + 1]]) }

/// Read one 32-bit field. # C: O(1)
fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Read one 64-bit field. # C: O(1)
fn le64(bytes: &[u8], at: usize) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(out)
}

/// Decode and validate a boot sector.
///
/// The checks run in the order the reference runs them, and the order is part
/// of the contract: a FAT volume must be refused by the must-be-zero field
/// rather than by whatever its BPB happens to make of the later ones.
/// # C: O(1)
pub fn parse(bytes: &[u8]) -> Result<Boot, BootError> {
    if bytes.len() < MIN_BOOT_BYTES { return Err(BootError::TooShort); }
    if le16(bytes, OFF_SIGNATURE) != BOOT_SIGNATURE { return Err(BootError::BadSignature); }
    if &bytes[OFF_FS_NAME..OFF_FS_NAME + FS_NAME_LEN] != FS_NAME.as_slice() {
        return Err(BootError::NotExfat);
    }
    if bytes[OFF_MUST_BE_ZERO..OFF_MUST_BE_ZERO + MUST_BE_ZERO_LEN].iter().any(|b| *b != 0) {
        return Err(BootError::FatVolume);
    }

    let num_fats = bytes[OFF_NUM_FATS];
    if num_fats != 1 && num_fats != 2 { return Err(BootError::BadFatCount); }

    let sect_size_bits = bytes[OFF_SECT_SIZE_BITS];
    if !(MIN_SECT_SIZE_BITS..=MAX_SECT_SIZE_BITS).contains(&sect_size_bits) {
        return Err(BootError::BadSectorSize);
    }
    let sect_per_clus_bits = bytes[OFF_SECT_PER_CLUS_BITS];
    if sect_per_clus_bits > MAX_CLUSTER_SIZE_BITS - sect_size_bits {
        return Err(BootError::BadClusterSize);
    }

    let boot = Boot {
        partition_offset: le64(bytes, OFF_PARTITION_OFFSET),
        vol_length: le64(bytes, OFF_VOL_LENGTH),
        fat_offset: le32(bytes, OFF_FAT_OFFSET),
        fat_length: le32(bytes, OFF_FAT_LENGTH),
        clu_offset: le32(bytes, OFF_CLU_OFFSET),
        clu_count: le32(bytes, OFF_CLU_COUNT),
        root_cluster: le32(bytes, OFF_ROOT_CLUSTER),
        vol_serial: le32(bytes, OFF_VOL_SERIAL),
        fs_revision: [bytes[OFF_FS_REVISION], bytes[OFF_FS_REVISION + 1]],
        vol_flags: le16(bytes, OFF_VOL_FLAGS),
        sect_size_bits,
        sect_per_clus_bits,
        num_fats,
        drv_sel: bytes[OFF_DRV_SEL],
        percent_in_use: bytes[OFF_PERCENT_IN_USE],
    };

    // The table must hold a four-byte entry for every cluster, the two
    // reserved ones included.
    let num_clusters = u64::from(boot.clu_count) + u64::from(RESERVED_CLUSTERS);
    if (u64::from(boot.fat_length) << sect_size_bits) < num_clusters * FAT_ENTRY_BYTES as u64 {
        return Err(BootError::BadFatLength);
    }
    // The heap cannot start inside the tables, or a cluster read returns table
    // bytes.
    if u64::from(boot.clu_offset)
        < u64::from(boot.fat_offset) + u64::from(boot.fat_length) * u64::from(num_fats) {
        return Err(BootError::BadDataStart);
    }
    Ok(boot)
}

/// Whether the volume's last owner left it dirty. # C: O(1)
pub fn is_dirty(boot: &Boot) -> bool { boot.vol_flags & VOLUME_DIRTY != 0 }

/// Whether the medium has reported a failure. # C: O(1)
pub fn media_failure(boot: &Boot) -> bool { boot.vol_flags & MEDIA_FAILURE != 0 }

/// The flags word a mount writes back when it sets or clears dirty.
///
/// The two persistent flags a mount did not set are carried forward: clearing
/// a medium-failure bit this mount did not repair tells the next reader the
/// medium is sound when nobody has checked.
/// # C: O(1)
pub fn flags_with_dirty(current: u16, dirty: bool) -> u16 {
    let persistent = current & VOLUME_PERSISTENT_FLAGS & !VOLUME_DIRTY;
    persistent | if dirty { VOLUME_DIRTY } else { 0 }
}

/// Write the volume flags into a boot sector's bytes. # C: O(1)
pub fn set_vol_flags(bytes: &mut [u8], flags: u16) {
    bytes[OFF_VOL_FLAGS..OFF_VOL_FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
}

/// Write the in-use percentage into a boot sector's bytes.
///
/// Neither this byte nor the flags word contributes to the boot checksum, so a
/// mount that changes them does not have to rewrite eleven sectors and their
/// checksum sector to keep the region valid.
/// # C: O(1)
pub fn set_percent_in_use(bytes: &mut [u8], percent: u8) { bytes[OFF_PERCENT_IN_USE] = percent; }

/// The percentage a volume with `used` of `total` clusters allocated reports.
///
/// Rounds DOWN, and a volume with anything free never reports full: an
/// almost-full volume reporting 100 tells a user there is nothing left when
/// there is.
/// # C: O(1)
pub fn percent_in_use(used: u64, total: u64) -> u8 {
    if total == 0 { return 0; }
    let pct = used.saturating_mul(100) / total;
    let pct = u8::try_from(pct).unwrap_or(100);
    if pct == 100 && used < total { 99 } else { pct }
}

#[cfg(test)]
#[path = "tests/boot.rs"]
pub(crate) mod tests;
