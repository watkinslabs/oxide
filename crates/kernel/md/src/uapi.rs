//! Linux MD ioctl wire definitions and immutable query replies.

/// `mdu_version_t` byte width on both supported 64-bit ABIs.
pub const VERSION_BYTES: usize = 12;
/// `mdu_array_info_t` byte width on both supported 64-bit ABIs.
pub const ARRAY_INFO_BYTES: usize = 72;
/// `mdu_disk_info_t` byte width on both supported 64-bit ABIs.
pub const DISK_INFO_BYTES: usize = 20;

const IOC_READ: u64 = 2;
const IOC_TYPESHIFT: u64 = 8;
const IOC_SIZESHIFT: u64 = 16;
const IOC_DIRSHIFT: u64 = 30;

/// MD ioctl version major reported by `RAID_VERSION`.
pub const MD_MAJOR_VERSION: i32 = 0;
/// MD ioctl version minor reported by `RAID_VERSION`.
pub const MD_MINOR_VERSION: i32 = 90;
/// MD ioctl patch level reported by `RAID_VERSION` and array information.
pub const MD_PATCHLEVEL_VERSION: i32 = 3;

/// `RAID_VERSION`, `_IOR(9, 0x10, mdu_version_t)`.
pub const RAID_VERSION: u64 = ior(0x10, VERSION_BYTES as u64);
/// `GET_ARRAY_INFO`, `_IOR(9, 0x11, mdu_array_info_t)`.
pub const GET_ARRAY_INFO: u64 = ior(0x11, ARRAY_INFO_BYTES as u64);
/// `GET_DISK_INFO`, `_IOR(9, 0x12, mdu_disk_info_t)`.
pub const GET_DISK_INFO: u64 = ior(0x12, DISK_INFO_BYTES as u64);

/// A `RAID_VERSION` reply. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Version { pub major: i32, pub minor: i32, pub patchlevel: i32 }

impl Version {
    /// Linux MD ioctl interface version. # C: O(1)
    pub const fn current() -> Self {
        Self { major: MD_MAJOR_VERSION, minor: MD_MINOR_VERSION, patchlevel: MD_PATCHLEVEL_VERSION }
    }

    /// Encode the native-endian Linux `mdu_version_t` reply. # C: O(1)
    pub fn encode(self) -> [u8; VERSION_BYTES] {
        let mut bytes = [0; VERSION_BYTES];
        put_i32(&mut bytes, 0, self.major); put_i32(&mut bytes, 4, self.minor); put_i32(&mut bytes, 8, self.patchlevel);
        bytes
    }
}

/// A `GET_ARRAY_INFO` reply. All fields match `mdu_array_info_t` exactly.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ArrayInfo {
    pub major_version: i32, pub minor_version: i32, pub patch_version: i32, pub ctime: u32,
    pub level: i32, pub size: i32, pub nr_disks: i32, pub raid_disks: i32, pub md_minor: i32, pub not_persistent: i32,
    pub utime: u32, pub state: i32, pub active_disks: i32, pub working_disks: i32, pub failed_disks: i32, pub spare_disks: i32,
    pub layout: i32, pub chunk_size: i32,
}

impl ArrayInfo {
    /// Encode the native-endian Linux `mdu_array_info_t` reply. # C: O(1)
    pub fn encode(self) -> [u8; ARRAY_INFO_BYTES] {
        let mut bytes = [0; ARRAY_INFO_BYTES];
        put_i32(&mut bytes, 0, self.major_version); put_i32(&mut bytes, 4, self.minor_version); put_i32(&mut bytes, 8, self.patch_version);
        put_u32(&mut bytes, 12, self.ctime); put_i32(&mut bytes, 16, self.level); put_i32(&mut bytes, 20, self.size);
        put_i32(&mut bytes, 24, self.nr_disks); put_i32(&mut bytes, 28, self.raid_disks); put_i32(&mut bytes, 32, self.md_minor);
        put_i32(&mut bytes, 36, self.not_persistent); put_u32(&mut bytes, 40, self.utime); put_i32(&mut bytes, 44, self.state);
        put_i32(&mut bytes, 48, self.active_disks); put_i32(&mut bytes, 52, self.working_disks); put_i32(&mut bytes, 56, self.failed_disks);
        put_i32(&mut bytes, 60, self.spare_disks); put_i32(&mut bytes, 64, self.layout); put_i32(&mut bytes, 68, self.chunk_size);
        bytes
    }
}

/// A `GET_DISK_INFO` reply. The caller supplies only `number` before this
/// complete native-endian `mdu_disk_info_t` reply replaces its buffer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DiskInfo { pub number: i32, pub major: i32, pub minor: i32, pub raid_disk: i32, pub state: i32 }

impl DiskInfo {
    /// Decode the caller-selected persistent member number. # C: O(1)
    pub fn requested_number(bytes: &[u8; DISK_INFO_BYTES]) -> i32 { i32::from_ne_bytes(bytes[..4].try_into().expect("fixed width")) }

    /// Encode the native-endian Linux `mdu_disk_info_t` reply. # C: O(1)
    pub fn encode(self) -> [u8; DISK_INFO_BYTES] {
        let mut bytes = [0; DISK_INFO_BYTES];
        put_i32(&mut bytes, 0, self.number); put_i32(&mut bytes, 4, self.major); put_i32(&mut bytes, 8, self.minor);
        put_i32(&mut bytes, 12, self.raid_disk); put_i32(&mut bytes, 16, self.state); bytes
    }
}

const fn ior(number: u64, size: u64) -> u64 { (IOC_READ << IOC_DIRSHIFT) | (size << IOC_SIZESHIFT) | ((crate::MD_MAJOR as u64) << IOC_TYPESHIFT) | number }
fn put_i32(bytes: &mut [u8], at: usize, value: i32) { bytes[at..at + 4].copy_from_slice(&value.to_ne_bytes()); }
fn put_u32(bytes: &mut [u8], at: usize, value: u32) { bytes[at..at + 4].copy_from_slice(&value.to_ne_bytes()); }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_md_ioctl_numbers_and_native_layouts_are_exact() {
        assert_eq!((RAID_VERSION, GET_ARRAY_INFO, GET_DISK_INFO), (0x800c_0910, 0x8048_0911, 0x8014_0912));
        assert_eq!(Version::current().encode(), [0, 0, 0, 0, 90, 0, 0, 0, 3, 0, 0, 0]);
        let info = ArrayInfo { major_version: 1, minor_version: 2, patch_version: 3, ctime: 4, level: -1, size: 6, nr_disks: 2, raid_disks: 2, md_minor: 7, not_persistent: 0, utime: 8, state: 1, active_disks: 2, working_disks: 2, failed_disks: 0, spare_disks: 0, layout: 9, chunk_size: 10 };
        assert_eq!(info.encode().len(), ARRAY_INFO_BYTES); assert_eq!(&info.encode()[16..24], &[0xff, 0xff, 0xff, 0xff, 6, 0, 0, 0]);
        let disk = DiskInfo { number: 4, major: 8, minor: 1, raid_disk: 0, state: 6 };
        assert_eq!(DiskInfo::requested_number(&disk.encode()), 4); assert_eq!(&disk.encode()[4..], &[8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0]);
    }
}
