//! Inode-owned Windows file attributes shared by every NT file operation.

pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;

const USER_ATTRIBUTES: u32 = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN
    | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE;

/// Canonical Windows attribute word for one VFS inode. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowsFileAttributes(u32);

impl WindowsFileAttributes {
    /// Derive the initial Windows projection without changing Linux mode bits. # C: O(1)
    pub const fn initial(is_directory: bool, readonly: bool) -> Self {
        let mut value = if is_directory { FILE_ATTRIBUTE_DIRECTORY } else { FILE_ATTRIBUTE_ARCHIVE };
        if readonly { value |= FILE_ATTRIBUTE_READONLY; }
        Self(value)
    }

    /// Construct a validated caller-supplied Windows attribute word. # C: O(1)
    pub const fn from_raw(value: u32, is_directory: bool) -> Option<Self> {
        let directory = value & FILE_ATTRIBUTE_DIRECTORY != 0;
        if directory != is_directory || value & !(USER_ATTRIBUTES | FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return None;
        }
        Some(Self(value))
    }

    /// Return the ABI word. # C: O(1)
    pub const fn raw(self) -> u32 { self.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_projection_tracks_type_and_posix_readonly() {
        assert_eq!(WindowsFileAttributes::initial(false, false).raw(), FILE_ATTRIBUTE_ARCHIVE);
        assert_eq!(WindowsFileAttributes::initial(false, true).raw(), FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_READONLY);
        assert_eq!(WindowsFileAttributes::initial(true, false).raw(), FILE_ATTRIBUTE_DIRECTORY);
    }

    #[test]
    fn validated_updates_preserve_directory_identity_and_known_bits() {
        assert!(WindowsFileAttributes::from_raw(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, false).is_some());
        assert!(WindowsFileAttributes::from_raw(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN, true).is_some());
        assert!(WindowsFileAttributes::from_raw(FILE_ATTRIBUTE_DIRECTORY, false).is_none());
        assert!(WindowsFileAttributes::from_raw(FILE_ATTRIBUTE_HIDDEN | (1 << 31), false).is_none());
    }
}
