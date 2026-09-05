//! NT file-create disposition decisions shared by the kernel adapter tests.

use syscall::errno::Errno;
use vfs::Timespec64;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum CreateDisposition {
    Supersede,
    Open,
    Create,
    OpenIf,
    Overwrite,
    OverwriteIf,
}

const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
const DELETE_ACCESS: u32 = 0x0001_0000;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
const STATUS_OBJECT_NAME_COLLISION: u64 = 0xc000_0035;
const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const NT_FILETIME_EPOCH_SECONDS: i64 = 11_644_473_600;

const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;
const UNSUPPORTED_FILE_ACCESS: u32 = 0x0008;
const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x1000_0000;
const POSIX_WRITE_BITS: u32 = 0o222;
const FILE_DIRECTORY_INFORMATION: u32 = 1;
const FILE_FULL_DIRECTORY_INFORMATION: u32 = 2;
const FILE_BOTH_DIRECTORY_INFORMATION: u32 = 3;
const FILE_NAMES_INFORMATION: u32 = 12;
const FILE_ID_BOTH_DIRECTORY_INFORMATION: u32 = 37;

/// Translate `FILE_ATTRIBUTE_READONLY` on a newly-created NT node into the
/// mode passed to the canonical VFS create owner. # C: O(1)
pub(crate) const fn creation_mode(file_attributes: u32, directory: bool) -> u32 {
    if directory {
        if file_attributes & FILE_ATTRIBUTE_READONLY != 0 { 0o555 } else { 0o777 }
    } else if file_attributes & FILE_ATTRIBUTE_READONLY != 0 { 0o444 } else { 0o666 }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryInfoLayout {
    pub(crate) header: usize,
    pub(crate) name_length: usize,
    pub(crate) name: usize,
    pub(crate) attributes: Option<usize>,
    pub(crate) ea_size: Option<usize>,
    pub(crate) file_id: Option<usize>,
}

/// Select the NT directory record layout consumed by the VFS emitter. # C: O(1)
pub(crate) const fn directory_info_layout(class: u32) -> Option<DirectoryInfoLayout> {
    match class {
        FILE_DIRECTORY_INFORMATION => Some(DirectoryInfoLayout { header: 64, name_length: 60, name: 64,
            attributes: Some(56), ea_size: None, file_id: None }),
        FILE_FULL_DIRECTORY_INFORMATION => Some(DirectoryInfoLayout { header: 68, name_length: 60, name: 68,
            attributes: Some(56), ea_size: Some(64), file_id: None }),
        FILE_BOTH_DIRECTORY_INFORMATION => Some(DirectoryInfoLayout { header: 94, name_length: 60, name: 94,
            attributes: Some(56), ea_size: Some(64), file_id: None }),
        FILE_NAMES_INFORMATION => Some(DirectoryInfoLayout { header: 12, name_length: 8, name: 12,
            attributes: None, ea_size: None, file_id: None }),
        FILE_ID_BOTH_DIRECTORY_INFORMATION => Some(DirectoryInfoLayout { header: 104, name_length: 60, name: 104,
            attributes: Some(56), ea_size: Some(64), file_id: Some(96) }),
        _ => None,
    }
}

/// Translate the canonical VFS mode into the DOS attributes exposed by NT.
/// Directories keep their directory bit; read-only is meaningful for files
/// when no POSIX write owner, group, or other bit remains. # C: O(1)
pub(crate) const fn file_attributes(mode: u32, is_directory: bool) -> u32 {
    let base = if is_directory { FILE_ATTRIBUTE_DIRECTORY } else { FILE_ATTRIBUTE_ARCHIVE };
    if !is_directory && mode & POSIX_WRITE_BITS == 0 { base | FILE_ATTRIBUTE_READONLY } else { base }
}

/// NT creation time uses the VFS birth time when the owner stores one. A VFS
/// owner without birth time reports the modification time, matching NT's
/// Unix-backed fallback rather than exposing Linux change time as creation. # C: O(1)
pub(crate) const fn creation_time(stat: &vfs::Kstat) -> vfs::Timespec64 {
    match stat.btime { Some(time) => time, None => stat.mtime }
}

/// Admit the NT open access classes that can produce a file object. A zero
/// access mask is a metadata-only open; data access remains unavailable on
/// the handle inserted by the caller. # C: O(1)
pub(crate) const fn access_mask_admits_open(desired: u32) -> bool {
    desired == 0 || desired & (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE_ACCESS) != 0
}

impl CreateDisposition {
    pub(crate) const fn decode(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Supersede), 1 => Some(Self::Open), 2 => Some(Self::Create),
            3 => Some(Self::OpenIf), 4 => Some(Self::Overwrite), 5 => Some(Self::OverwriteIf),
            _ => None,
        }
    }
    pub(crate) const fn allows_missing(self) -> bool {
        matches!(self, Self::Supersede | Self::Create | Self::OpenIf | Self::OverwriteIf)
    }
    pub(crate) const fn rejects_existing(self) -> bool { matches!(self, Self::Create) }
    pub(crate) const fn truncates_existing(self) -> bool {
        matches!(self, Self::Supersede | Self::Overwrite | Self::OverwriteIf)
    }
}

pub(crate) const fn delete_on_close_access_valid(options: u32, desired: u32) -> bool {
    options & FILE_DELETE_ON_CLOSE == 0 || desired & DELETE_ACCESS != 0
}

/// Decode a Windows FILETIME field for `FileBasicInformation`. Zero and
/// `-1` are the NT leave-unchanged values; every other value is a positive
/// count of 100-ns intervals since 1601 and is converted to the VFS's signed
/// `timespec64` owner without narrowing through nanoseconds. # C: O(1)
pub(crate) const fn filetime_to_timespec(value: i64) -> Option<Timespec64> {
    if value == 0 || value == -1 || value < 0 { return None; }
    let ticks = value as u64;
    let seconds = ticks / 10_000_000;
    let nanos = (ticks % 10_000_000) * 100;
    if seconds < NT_FILETIME_EPOCH_SECONDS as u64 { return None; }
    Some(Timespec64::new((seconds - NT_FILETIME_EPOCH_SECONDS as u64) as i64, nanos as u32))
}

/// Validate the fields not yet represented by the Linux-shaped inode
/// metadata owner. Creation/change time are kernel-owned, while Windows file
/// attributes are accepted only when they already equal the object's canonical
/// projection; callers never receive success for a discarded request. # C: O(1)
pub(crate) const fn file_basic_unsupported_fields(
    creation: i64, change: i64, attributes: u32, current_attributes: u32,
) -> bool {
    (creation != 0 && creation != -1) || (change != 0 && change != -1)
        || (attributes != 0 && attributes != current_attributes)
}

/// Preserve the Linux VFS errno distinction at the NT file boundary. # C: O(1)
pub(crate) fn status_from_errno(rv: i64) -> u64 {
    match rv.unsigned_abs() as i32 {
        value if value == Errno::Enoent.as_i32() => STATUS_OBJECT_NAME_NOT_FOUND,
        value if value == Errno::Eexist.as_i32() => STATUS_OBJECT_NAME_COLLISION,
        value if value == Errno::Eacces.as_i32() => STATUS_ACCESS_DENIED,
        _ => STATUS_INVALID_PARAMETER,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_the_six_nt_create_dispositions() {
        for value in 0..=5 { assert!(CreateDisposition::decode(value).is_some()); }
        assert!(CreateDisposition::decode(6).is_none());
    }
    #[test]
    fn disposition_matrix_preserves_create_and_overwrite_semantics() {
        assert!(CreateDisposition::decode(2).unwrap().rejects_existing());
        assert!(!CreateDisposition::decode(1).unwrap().allows_missing());
        assert!(CreateDisposition::decode(3).unwrap().allows_missing());
        assert!(CreateDisposition::decode(4).unwrap().truncates_existing());
        assert!(CreateDisposition::decode(5).unwrap().truncates_existing());
        assert!(!CreateDisposition::decode(3).unwrap().truncates_existing());
    }

    #[test]
    fn delete_on_close_requires_delete_access() {
        assert!(delete_on_close_access_valid(0, 0));
        assert!(!delete_on_close_access_valid(FILE_DELETE_ON_CLOSE, 0));
        assert!(delete_on_close_access_valid(FILE_DELETE_ON_CLOSE, DELETE_ACCESS));
    }

    #[test]
    fn filetime_decoder_preserves_subsecond_and_unchanged_values() {
        assert_eq!(filetime_to_timespec(0), None);
        assert_eq!(filetime_to_timespec(-1), None);
        assert_eq!(filetime_to_timespec(116444736000000001),
            Some(Timespec64::new(0, 100)));
        assert_eq!(filetime_to_timespec(116444735999999999), None);
    }

    #[test]
    fn file_basic_rejects_fields_that_cannot_be_discarded() {
        assert!(!file_basic_unsupported_fields(0, -1, 0x80, 0x80));
        assert!(file_basic_unsupported_fields(1, 0, 0x80, 0x80));
        assert!(file_basic_unsupported_fields(0, 1, 0x80, 0x80));
        assert!(file_basic_unsupported_fields(0, 0, 1, 0x80));
    }

    #[test]
    fn metadata_only_zero_access_open_is_admitted_without_data_rights() {
        assert!(access_mask_admits_open(0));
        assert!(access_mask_admits_open(DELETE_ACCESS));
        assert!(!access_mask_admits_open(UNSUPPORTED_FILE_ACCESS));
    }

    #[test]
    fn errno_mapping_preserves_file_failure_classes() {
        assert_eq!(status_from_errno(-(Errno::Enoent.as_i32() as i64)), STATUS_OBJECT_NAME_NOT_FOUND);
        assert_eq!(status_from_errno(-(Errno::Eexist.as_i32() as i64)), STATUS_OBJECT_NAME_COLLISION);
        assert_eq!(status_from_errno(-(Errno::Eacces.as_i32() as i64)), STATUS_ACCESS_DENIED);
        assert_eq!(status_from_errno(-(Errno::Eio.as_i32() as i64)), STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn basic_information_translation_preserves_vfs_readonly_and_birth_fallback() {
        let stat = vfs::Kstat { mode: 0o100_444, mtime: vfs::Timespec64::from_secs(22),
            ctime: vfs::Timespec64::from_secs(99), ..Default::default() };
        assert_eq!(file_attributes(stat.mode, false), FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_READONLY);
        assert_eq!(file_attributes(0o100_644, false), FILE_ATTRIBUTE_ARCHIVE);
        assert_eq!(file_attributes(0o040_555, true), FILE_ATTRIBUTE_DIRECTORY);
        assert_eq!(creation_time(&stat), vfs::Timespec64::from_secs(22));
    }

    #[test]
    fn directory_layout_exposes_file_id_both_record() {
        let layout = directory_info_layout(FILE_ID_BOTH_DIRECTORY_INFORMATION).unwrap();
        assert_eq!(layout.header, 104);
        assert_eq!(layout.name, 104);
        assert_eq!(layout.file_id, Some(96));
        assert_eq!(directory_info_layout(36), None);
    }

    #[test]
    fn readonly_creation_removes_all_write_bits() {
        assert_eq!(creation_mode(FILE_ATTRIBUTE_READONLY, false), 0o444);
        assert_eq!(creation_mode(FILE_ATTRIBUTE_READONLY, true), 0o555);
        assert_eq!(creation_mode(0, false), 0o666);
        assert_eq!(creation_mode(0, true), 0o777);
    }

}
