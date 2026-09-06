use super::NtFileInfo;
use vfs::types::FileType;

#[test]
fn wine_descriptor_metadata_preserves_open_options() {
    let info = NtFileInfo::for_type(FileType::Regular, 0x1234_5678);
    assert_eq!(info.fd_type, NtFileInfo::FD_TYPE_FILE);
    assert_eq!(info.cacheable, 1);
    assert_eq!(info.options, 0x1234_5678);
}

#[test]
fn wine_descriptor_metadata_classifies_non_files() {
    let cases = [
        (FileType::Directory, NtFileInfo::FD_TYPE_DIR, 1),
        (FileType::Socket, NtFileInfo::FD_TYPE_SOCKET, 0),
        (FileType::CharDev, NtFileInfo::FD_TYPE_CHAR, 0),
        (FileType::Fifo, NtFileInfo::FD_TYPE_CHAR, 0),
        (FileType::Symlink, NtFileInfo::FD_TYPE_CHAR, 0),
    ];
    for (file_type, fd_type, cacheable) in cases {
        let info = NtFileInfo::for_type(file_type, 0);
        assert_eq!((info.fd_type, info.cacheable), (fd_type, cacheable));
    }
}
