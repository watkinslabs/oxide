//! File descriptor metadata derived from canonical VFS type.
use super::NtFileInfo;
impl NtFileInfo {
    /// Wine server descriptor classes used by `get_handle_fd`.
    pub const FD_TYPE_FILE: u32 = 1;
    pub const FD_TYPE_DIR: u32 = 2;
    pub const FD_TYPE_SOCKET: u32 = 3;
    pub const FD_TYPE_CHAR: u32 = 5;

    /// Derive the Wine descriptor class from the VFS inode and retain NT open options. # C: O(1)
    pub fn from_file(file: &vfs::File, options: u32) -> Self {
        Self::for_type(file.inode().file_type(), options)
    }

    /// Derive descriptor metadata from the inode class. # C: O(1)
    pub fn for_type(file_type: vfs::types::FileType, options: u32) -> Self {
        let (fd_type, cacheable) = match file_type {
            vfs::types::FileType::Regular | vfs::types::FileType::BlockDev => (Self::FD_TYPE_FILE, 1),
            vfs::types::FileType::Directory => (Self::FD_TYPE_DIR, 1),
            vfs::types::FileType::Socket => (Self::FD_TYPE_SOCKET, 0),
            vfs::types::FileType::CharDev | vfs::types::FileType::Fifo | vfs::types::FileType::Symlink => (Self::FD_TYPE_CHAR, 0),
        };
        Self { fd_type, cacheable, options }
    }
}
