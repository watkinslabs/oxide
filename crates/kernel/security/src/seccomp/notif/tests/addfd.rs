// Descriptor injection: the half that does not need a running task.

use super::*;

// A supervisor is told why the injection failed, not a flattened EINVAL: a
// full descriptor table and a target number it may not use are different
// problems with different fixes.
#[test]
fn a_failed_install_reports_the_descriptor_tables_own_error() {
    assert_eq!(install_errno(VfsError::Emfile), Errno::Emfile);
    assert_eq!(install_errno(VfsError::Ebadf), Errno::Ebadf);
    assert_eq!(install_errno(VfsError::Ebusy), Errno::Ebusy);
    assert_eq!(install_errno(VfsError::Einval), Errno::Einval);
}

// The descriptor lands where the supervisor asked: at a number it chose when
// it said so, at the lowest free one otherwise, carrying only close-on-exec.
#[test]
fn an_injection_installs_where_the_request_says_and_replaces_what_is_there() {
    let fdt = vfs::FdTable::new();
    let first = fdt.install_limit(file(), vfs::OpenFlags::empty(), 8).unwrap();
    assert_eq!(first, 0);
    // Chosen number, over an occupied slot.
    let replacement = file();
    assert_eq!(fdt.replace_fd(0, replacement.clone(), vfs::OpenFlags::O_CLOEXEC, 8), Ok(0));
    assert!(Arc::ptr_eq(&fdt.get(0).unwrap(), &replacement));
    assert_eq!(fdt.cloexec(0), Ok(true));
    // Unchosen: the lowest free number.
    assert_eq!(fdt.install_limit(file(), vfs::OpenFlags::empty(), 8), Ok(1));
    assert_eq!(fdt.cloexec(1), Ok(false));
    // Beyond the target's limit the injection fails rather than growing it.
    assert_eq!(fdt.replace_fd(9, file(), vfs::OpenFlags::empty(), 8),
               Err(VfsError::Ebadf));
}

fn file() -> Arc<vfs::File> {
    let inode = vfs::InodeBuilder::new(1, vfs::mk_mode(vfs::FileType::Regular, 0o600),
        vfs::default_inode_ops(), vfs::default_file_ops()).build();
    let dentry = vfs::Dentry::new(None, alloc::string::String::from("f"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::empty())
}
