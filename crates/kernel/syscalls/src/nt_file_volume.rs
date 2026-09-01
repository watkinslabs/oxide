//! NT filesystem-information queries backed by the owning VFS superblock.

#![cfg(target_os = "oxide-kernel")]

use vfs::SbStatFs;

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const STATUS_INVALID_INFO_CLASS: u64 = 0xc000_0003;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_DEVICE_DISK: u32 = 7;
const FILE_DEVICE_SECURE_OPEN: u32 = 0x0000_0100;
const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
const FILE_PERSISTENT_ACLS: u32 = 0x0000_0008;
const FILE_SUPPORTS_OPEN_BY_FILE_ID: u32 = 0x0000_0100;
const FILE_FS_VOLUME_INFORMATION: u32 = 1;
const FILE_FS_SIZE_INFORMATION: u32 = 3;
const FILE_FS_DEVICE_INFORMATION: u32 = 4;
const FILE_FS_ATTRIBUTE_INFORMATION: u32 = 5;
const FILE_FS_FULL_SIZE_INFORMATION: u32 = 7;
const BYTES_PER_SECTOR: u64 = 512;

/// Answer filesystem-information queries using the file's captured mount and
/// inode, preserving the VFS statfs owner and NT output framing. # C: O(1)
pub fn query(cur: &sched::Task, handle: u32, io_status: u64, information: u64, length: u32, class: u32) -> u64 {
    if io_status == 0 || information == 0 { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let native = sched::nt_object::NtHandle::from_raw(handle);
    let Some(object) = table.get(native, FILE_READ_ATTRIBUTES) else {
        return if table.contains(native) { STATUS_ACCESS_DENIED } else { STATUS_INVALID_HANDLE };
    };
    let Some(file) = object.file() else { return STATUS_INVALID_HANDLE; };
    let Some(mount) = file.vfsmount() else { return STATUS_INVALID_HANDLE; };
    let Ok(stat) = mount.sb.statfs_at(file.inode()) else { return STATUS_INVALID_PARAMETER; };
    let (payload, required) = match encode(&stat, class) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if (length as usize) < required {
        return finish(io_status, STATUS_BUFFER_TOO_SMALL, 0);
    }
    if uaccess::copy_to_user(information, &payload).is_err() { return STATUS_ACCESS_VIOLATION; }
    if finish(io_status, STATUS_SUCCESS, required as u64) != STATUS_SUCCESS { return STATUS_ACCESS_VIOLATION; }
    STATUS_SUCCESS
}

fn finish(io_status: u64, status: u64, information: u64) -> u64 {
    if uaccess::put_user_u64(io_status, status).is_err()
        || uaccess::put_user_u64(io_status + 8, information).is_err() {
        STATUS_ACCESS_VIOLATION
    } else { status }
}

fn encode(stat: &SbStatFs, class: u32) -> Result<(alloc::vec::Vec<u8>, usize), u64> {
    match class {
        FILE_FS_DEVICE_INFORMATION => {
            let mut out = alloc::vec![0u8; 8];
            out[0..4].copy_from_slice(&FILE_DEVICE_DISK.to_le_bytes());
            out[4..8].copy_from_slice(&FILE_DEVICE_SECURE_OPEN.to_le_bytes());
            Ok((out, 8))
        }
        FILE_FS_SIZE_INFORMATION => {
            let (total, available, sectors) = allocation_units(stat);
            let mut out = alloc::vec![0u8; 24];
            out[0..8].copy_from_slice(&total.to_le_bytes());
            out[8..16].copy_from_slice(&available.to_le_bytes());
            out[16..20].copy_from_slice(&sectors.to_le_bytes());
            out[20..24].copy_from_slice(&(BYTES_PER_SECTOR as u32).to_le_bytes());
            Ok((out, 24))
        }
        FILE_FS_FULL_SIZE_INFORMATION => {
            let (total, available, sectors) = allocation_units(stat);
            let mut out = alloc::vec![0u8; 32];
            out[0..8].copy_from_slice(&total.to_le_bytes());
            out[8..16].copy_from_slice(&available.to_le_bytes());
            out[16..24].copy_from_slice(&available.to_le_bytes());
            out[24..28].copy_from_slice(&sectors.to_le_bytes());
            out[28..32].copy_from_slice(&(BYTES_PER_SECTOR as u32).to_le_bytes());
            Ok((out, 32))
        }
        FILE_FS_ATTRIBUTE_INFORMATION => {
            let name = filesystem_name(stat.f_type);
            let mut out = alloc::vec![0u8; 12 + name.len() * 2];
            let attrs = FILE_CASE_PRESERVED_NAMES | FILE_PERSISTENT_ACLS | FILE_SUPPORTS_OPEN_BY_FILE_ID;
            out[0..4].copy_from_slice(&attrs.to_le_bytes());
            out[4..8].copy_from_slice(&(255u32).to_le_bytes());
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

fn allocation_units(stat: &SbStatFs) -> (u64, u64, u32) {
    let bytes = u64::from(stat.f_bsize.max(BYTES_PER_SECTOR as u32));
    let sectors = (bytes / BYTES_PER_SECTOR).max(1) as u32;
    let total = stat.f_blocks / u64::from(sectors);
    let available = stat.f_bavail / u64::from(sectors);
    (total, available, sectors)
}

fn filesystem_name(magic: u64) -> &'static [u8] {
    match magic {
        0x9660 => b"CDFS",
        0x1501_3346 => b"UDF",
        0x4d44 => b"FAT32",
        _ => b"NTFS",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_information_matches_disk_shape() {
        let (out, required) = encode(&SbStatFs::default(), FILE_FS_DEVICE_INFORMATION).unwrap();
        assert_eq!(required, 8);
        assert_eq!(&out, &[7, 0, 0, 0, 0, 1, 0, 0]);
    }

    #[test]
    fn size_information_uses_vfs_block_accounting() {
        let stat = SbStatFs { f_bsize: 4096, f_blocks: 8192, f_bavail: 4096, ..Default::default() };
        let (out, required) = encode(&stat, FILE_FS_SIZE_INFORMATION).unwrap();
        assert_eq!(required, 24);
        assert_eq!(u64::from_le_bytes(out[0..8].try_into().unwrap()), 1024);
        assert_eq!(u64::from_le_bytes(out[8..16].try_into().unwrap()), 512);
        assert_eq!(u32::from_le_bytes(out[16..20].try_into().unwrap()), 8);
    }

    #[test]
    fn unsupported_information_class_is_not_silent_success() {
        assert_eq!(encode(&SbStatFs::default(), 99), Err(STATUS_INVALID_INFO_CLASS));
    }
}
