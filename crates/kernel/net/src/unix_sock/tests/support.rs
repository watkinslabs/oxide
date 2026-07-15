use super::*;

struct NullOps;
impl vfs::FileOps for NullOps {
    fn read(&self, _i: &vfs::inode::Inode, _o: u64, b: &mut [u8]) -> vfs::KResult<usize> { Ok(b.len()) }
    fn write(&self, _i: &vfs::inode::Inode, _o: u64, b: &[u8]) -> vfs::KResult<usize> { Ok(b.len()) }
}

/// Create a socket-typed file for SCM_RIGHTS fixtures. # C: O(1)
pub(super) fn anon_file() -> alloc::sync::Arc<vfs::File> {
    let ino: vfs::InodeRef = vfs::InodeBuilder::new(
        0xF00D,
        vfs::mk_mode(vfs::FileType::Socket, 0o600),
        vfs::default_inode_ops(),
        alloc::sync::Arc::new(NullOps),
    ).build();
    let d = vfs::Dentry::new(None, "s".into(), alloc::sync::Arc::clone(&ino));
    vfs::File::new_at(ino, d, vfs::OpenFlags::O_RDWR, 0, vfs::FileCred::root())
}
