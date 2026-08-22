use vfs::VfsError;

#[test]
fn key_and_message_errnos_survive_posix_reconstruction() {
    for error in [VfsError::Enopkg, VfsError::Ebadmsg, VfsError::Enokey,
                  VfsError::Ekeyrejected]
    {
        assert_eq!(VfsError::from_posix_errno(error as i32), error);
    }
}
