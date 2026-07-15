extern crate alloc;

use alloc::sync::Arc;

/// Reserve and publish an nsfs file with `FD_CLOEXEC` set before visibility. # C: O(fd words)
pub(crate) fn install(fdt: &vfs::FdTable, file: Arc<vfs::File>, nofile: usize)
    -> vfs::KResult<i32>
{
    fdt.install_limit(file, vfs::OpenFlags::O_CLOEXEC, nofile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> Arc<vfs::File> {
        let inode = vfs::InodeBuilder::new(
            0x534b_4e53, vfs::mk_mode(vfs::FileType::Regular, 0o444),
            vfs::default_inode_ops(), vfs::default_file_ops(),
        ).build();
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("net"), inode.clone());
        vfs::File::new(inode, dentry, vfs::OpenFlags::empty())
    }

    #[test]
    fn namespace_fd_is_cloexec_at_first_publication() {
        let fdt = vfs::FdTable::new();
        let fd = install(&fdt, file(), 8).unwrap();
        assert!(fdt.get(fd).is_ok());
        assert_eq!(fdt.cloexec(fd), Ok(true));
        fdt.close_on_exec();
        assert_eq!(fdt.get(fd).err(), Some(vfs::VfsError::Ebadf));
    }

    #[test]
    fn namespace_fd_limit_failure_publishes_nothing_and_leaves_slot_reusable() {
        let fdt = vfs::FdTable::new();
        assert_eq!(install(&fdt, file(), 0), Err(vfs::VfsError::Emfile));
        assert!(fdt.live_fds().is_empty());
        assert_eq!(install(&fdt, file(), 1), Ok(0));
        assert_eq!(fdt.cloexec(0), Ok(true));
    }

    #[test]
    fn namespace_fd_install_and_close_reuse_have_complete_linearizations() {
        let close_first = vfs::FdTable::new();
        close_first.close_range(0, 0, false);
        assert_eq!(install(&close_first, file(), 1), Ok(0));
        assert!(close_first.get(0).is_ok());
        assert_eq!(close_first.cloexec(0), Ok(true));

        let install_first = vfs::FdTable::new();
        assert_eq!(install(&install_first, file(), 1), Ok(0));
        install_first.close_range(0, 0, false);
        assert_eq!(install_first.get(0).err(), Some(vfs::VfsError::Ebadf));
        assert_eq!(install(&install_first, file(), 1), Ok(0));
        assert_eq!(install_first.cloexec(0), Ok(true));
    }
}
