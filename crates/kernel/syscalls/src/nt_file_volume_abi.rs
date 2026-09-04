//! Host-testable NT filesystem-information encoders backed by VFS statfs.

extern crate alloc;
use vfs::SbStatFs;

pub(crate) const FILE_FS_DEVICE_INFORMATION: u32 = 4;
pub(crate) const FILE_FS_SIZE_INFORMATION: u32 = 3;
pub(crate) const FILE_FS_ATTRIBUTE_INFORMATION: u32 = 5;
pub(crate) const FILE_FS_VOLUME_INFORMATION: u32 = 1;
pub(crate) const FILE_FS_FULL_SIZE_INFORMATION: u32 = 7;
pub(crate) const FILE_FS_FULL_SIZE_INFORMATION_EX: u32 = 14;
const STATUS_INVALID_INFO_CLASS: u64 = 0xc000_0003;
const BYTES_PER_SECTOR: u64 = 512;

pub(crate) fn encode(stat: &SbStatFs, class: u32) -> Result<(alloc::vec::Vec<u8>, usize), u64> {
    match class {
        FILE_FS_DEVICE_INFORMATION => {
            let mut out = alloc::vec![0u8; 8];
            out[0..4].copy_from_slice(&7u32.to_le_bytes());
            out[4..8].copy_from_slice(&0x100u32.to_le_bytes());
            Ok((out, 8))
        }
        FILE_FS_SIZE_INFORMATION => {
            let (total, available, _actual_available, sectors) = allocation_units(stat);
            let mut out = alloc::vec![0u8; 24];
            out[0..8].copy_from_slice(&total.to_le_bytes());
            out[8..16].copy_from_slice(&available.to_le_bytes());
            out[16..20].copy_from_slice(&sectors.to_le_bytes());
            out[20..24].copy_from_slice(&(BYTES_PER_SECTOR as u32).to_le_bytes());
            Ok((out, 24))
        }
        FILE_FS_FULL_SIZE_INFORMATION => {
            let (total, available, actual_available, sectors) = allocation_units(stat);
            let mut out = alloc::vec![0u8; 32];
            out[0..8].copy_from_slice(&total.to_le_bytes());
            out[8..16].copy_from_slice(&available.to_le_bytes());
            out[16..24].copy_from_slice(&actual_available.to_le_bytes());
            out[24..28].copy_from_slice(&sectors.to_le_bytes());
            out[28..32].copy_from_slice(&(BYTES_PER_SECTOR as u32).to_le_bytes());
            Ok((out, 32))
        }
        FILE_FS_FULL_SIZE_INFORMATION_EX => {
            let (total, caller_available, actual_available, sectors) = allocation_units(stat);
            let used = total.saturating_sub(actual_available);
            let caller_total = caller_available.saturating_add(used);
            let mut out = alloc::vec![0u8; 96];
            out[0..8].copy_from_slice(&total.to_le_bytes());
            out[8..16].copy_from_slice(&actual_available.to_le_bytes());
            out[16..24].copy_from_slice(&0u64.to_le_bytes());
            out[24..32].copy_from_slice(&caller_total.to_le_bytes());
            out[32..40].copy_from_slice(&caller_available.to_le_bytes());
            out[40..48].copy_from_slice(&0u64.to_le_bytes());
            out[48..56].copy_from_slice(&used.to_le_bytes());
            out[56..64].copy_from_slice(&0u64.to_le_bytes());
            out[64..72].copy_from_slice(&0u64.to_le_bytes());
            out[72..80].copy_from_slice(&0u64.to_le_bytes());
            out[80..88].copy_from_slice(&0u64.to_le_bytes());
            out[88..92].copy_from_slice(&sectors.to_le_bytes());
            out[92..96].copy_from_slice(&(BYTES_PER_SECTOR as u32).to_le_bytes());
            Ok((out, 96))
        }
        FILE_FS_ATTRIBUTE_INFORMATION => {
            let name = filesystem_name(stat.f_type);
            let mut out = alloc::vec![0u8; 12 + name.len() * 2];
            out[0..4].copy_from_slice(&0x10au32.to_le_bytes());
            out[4..8].copy_from_slice(&255u32.to_le_bytes());
            out[8..12].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
            for (index, ch) in name.iter().enumerate() {
                out[12 + index * 2..14 + index * 2].copy_from_slice(&(*ch as u16).to_le_bytes());
            }
            Ok((out, 12 + name.len() * 2))
        }
        FILE_FS_VOLUME_INFORMATION => {
            let mut out = alloc::vec![0u8; 20];
            out[8..12].copy_from_slice(&(stat.f_fsid as u32).to_le_bytes());
            Ok((out, 20))
        }
        _ => Err(STATUS_INVALID_INFO_CLASS),
    }
}

fn allocation_units(stat: &SbStatFs) -> (u64, u64, u64, u32) {
    let bytes = u64::from(stat.f_bsize.max(BYTES_PER_SECTOR as u32));
    let sectors = (bytes / BYTES_PER_SECTOR).max(1) as u32;
    let divisor = u64::from(sectors);
    (stat.f_blocks / divisor, stat.f_bavail / divisor, stat.f_bfree / divisor, sectors)
}

fn filesystem_name(magic: u64) -> &'static [u8] {
    match magic { 0x9660 => b"CDFS", 0x1501_3346 => b"UDF", 0x4d44 => b"FAT32", _ => b"NTFS" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_size_ex_preserves_actual_and_caller_accounting() {
        let stat = SbStatFs { f_bsize: 4096, f_blocks: 8192, f_bfree: 6144, f_bavail: 4096, ..Default::default() };
        let (out, required) = encode(&stat, FILE_FS_FULL_SIZE_INFORMATION_EX).unwrap();
        assert_eq!(required, 96);
        assert_eq!(u64::from_le_bytes(out[0..8].try_into().unwrap()), 1024);
        assert_eq!(u64::from_le_bytes(out[8..16].try_into().unwrap()), 768);
        assert_eq!(u64::from_le_bytes(out[24..32].try_into().unwrap()), 768);
        assert_eq!(u64::from_le_bytes(out[32..40].try_into().unwrap()), 512);
        assert_eq!(u64::from_le_bytes(out[48..56].try_into().unwrap()), 256);
        assert_eq!(u32::from_le_bytes(out[88..92].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(out[92..96].try_into().unwrap()), 512);
    }

    #[test]
    fn full_size_information_uses_actual_free_blocks() {
        let stat = SbStatFs { f_bsize: 4096, f_blocks: 8192, f_bfree: 6144, f_bavail: 4096, ..Default::default() };
        let (out, _) = encode(&stat, FILE_FS_FULL_SIZE_INFORMATION).unwrap();
        assert_eq!(u64::from_le_bytes(out[16..24].try_into().unwrap()), 768);
    }

    #[test]
    fn size_information_reports_caller_available_units_and_sector_shape() {
        let stat = SbStatFs { f_bsize: 1024, f_blocks: 4096, f_bfree: 3072, f_bavail: 2048, ..Default::default() };
        let (out, required) = encode(&stat, FILE_FS_SIZE_INFORMATION).unwrap();
        assert_eq!(required, 24);
        assert_eq!(u64::from_le_bytes(out[0..8].try_into().unwrap()), 2048);
        assert_eq!(u64::from_le_bytes(out[8..16].try_into().unwrap()), 1024);
        assert_eq!(u32::from_le_bytes(out[16..20].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(out[20..24].try_into().unwrap()), 512);
    }

    #[test]
    fn unsupported_information_class_is_not_silent_success() {
        assert_eq!(encode(&SbStatFs::default(), 99), Err(STATUS_INVALID_INFO_CLASS));
    }
}
