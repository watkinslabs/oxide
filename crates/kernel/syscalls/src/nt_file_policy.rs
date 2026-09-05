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
pub(crate) const FILE_DISPOSITION_INFORMATION_SIZE: u32 = 1;
const NT_FILETIME_EPOCH_SECONDS: i64 = 11_644_473_600;

const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;
#[cfg(test)]
const UNSUPPORTED_FILE_ACCESS: u32 = 0x0008;
const FILE_ATTRIBUTE_READONLY: u32 = vfs::FILE_ATTRIBUTE_READONLY;
const FILE_DIRECTORY_INFORMATION: u32 = 1;
const FILE_FULL_DIRECTORY_INFORMATION: u32 = 2;
const FILE_BOTH_DIRECTORY_INFORMATION: u32 = 3;
const FILE_NAMES_INFORMATION: u32 = 12;
const FILE_ID_BOTH_DIRECTORY_INFORMATION: u32 = 37;
const FILE_WRITE_THROUGH: u32 = 0x0000_0002;
const FILE_SEQUENTIAL_ONLY: u32 = 0x0000_0004;
const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x0000_0008;
const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x0000_0010;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
#[cfg(test)]
const FILE_NON_DIRECTORY_OPTION: u32 = 0x0000_0040;

/// Translate `FILE_ATTRIBUTE_READONLY` on a newly-created NT node into the
/// mode passed to the canonical VFS create owner. # C: O(1)
pub(crate) const fn creation_mode(file_attributes: u32, directory: bool) -> u32 {
    if directory {
        if file_attributes & FILE_ATTRIBUTE_READONLY != 0 { 0o555 } else { 0o777 }
    } else if file_attributes & FILE_ATTRIBUTE_READONLY != 0 { 0o444 } else { 0o666 }
}

/// Return the open-option bits exposed by FileModeInformation; creation,
/// naming, and access options are intentionally absent from this result.
pub(crate) const fn file_mode_from_options(options: u32) -> u32 {
    options & (FILE_WRITE_THROUGH | FILE_SEQUENTIAL_ONLY
        | FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_ALERT
        | FILE_SYNCHRONOUS_IO_NONALERT)
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

/// Admit the open before any create, truncate, or share-state mutation. The
/// result is the deferred-delete state for the file object. # C: O(1)
pub(crate) const fn delete_on_close_admission(options: u32, desired: u32) -> Option<bool> {
    if !delete_on_close_access_valid(options, desired) { None }
    else { Some(options & FILE_DELETE_ON_CLOSE != 0) }
}

/// `DoDeleteFile` is a one-byte BOOLEAN; every nonzero value requests delete.
/// The length screen precedes handle lookup in the NT set-information path.
pub(crate) const fn disposition_information_valid(length: u32) -> bool {
    length >= FILE_DISPOSITION_INFORMATION_SIZE
}

pub(crate) const fn disposition_requests_delete(value: u8) -> bool { value != 0 }

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

/// Validate the fields still owned by the NT boundary. Creation/change time
/// remain kernel-owned; the VFS inode validates the Windows attribute word. # C: O(1)
pub(crate) const fn file_basic_unsupported_fields(
    creation: i64, change: i64,
) -> bool {
    (creation != 0 && creation != -1) || (change != 0 && change != -1)
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
    fn delete_on_close_admission_is_side_effect_free_and_reports_arming() {
        assert_eq!(delete_on_close_admission(0, 0), Some(false));
        assert_eq!(delete_on_close_admission(FILE_DELETE_ON_CLOSE, DELETE_ACCESS), Some(true));
        assert_eq!(delete_on_close_admission(FILE_DELETE_ON_CLOSE, 0), None);
    }

    #[test]
    fn disposition_uses_one_byte_boolean_and_accepts_any_nonzero_value() {
        assert!(!disposition_information_valid(0));
        assert!(disposition_information_valid(1));
        assert!(disposition_information_valid(8));
        assert!(!disposition_requests_delete(0));
        assert!(disposition_requests_delete(1));
        assert!(disposition_requests_delete(u8::MAX));
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
        assert!(!file_basic_unsupported_fields(0, -1));
        assert!(file_basic_unsupported_fields(1, 0));
        assert!(file_basic_unsupported_fields(0, 1));
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
    fn basic_information_translation_preserves_vfs_birth_fallback() {
        let stat = vfs::Kstat { mode: 0o100_444, mtime: vfs::Timespec64::from_secs(22),
            ctime: vfs::Timespec64::from_secs(99), ..Default::default() };
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

    #[test]
    fn file_mode_reports_only_windows_mode_options() {
        let mode = file_mode_from_options(FILE_WRITE_THROUGH | FILE_SEQUENTIAL_ONLY
            | FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_ALERT
            | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_OPTION);
        assert_eq!(mode, 0x3e);
    }

}
