use alloc::sync::Arc;

use crate::{Dentry, FdTable, File, FileType, InodeBuilder, InodeRef, OpenFlags, VfsError};
use crate::{default_file_ops, default_inode_ops, mk_mode};

fn file(ino: u64) -> Arc<File> {
    let inode: InodeRef = InodeBuilder::new(
        ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), default_file_ops(),
    ).build();
    let dentry = Dentry::new_root(Arc::clone(&inode));
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

#[test]
fn dup_file_min_limit_keeps_pinned_file_after_source_reuse() {
    let table = FdTable::new();
    let source = table.alloc(file(1)).unwrap();
    let pinned = table.get(source).unwrap();

    table.close(source).unwrap();
    let replacement = file(2);
    assert_eq!(table.alloc(Arc::clone(&replacement)).unwrap(), source);

    let duplicated = table.dup_file_min_limit(&pinned, 0, false, 8).unwrap();
    assert_eq!(duplicated, 1);
    assert!(Arc::ptr_eq(&table.get(duplicated).unwrap(), &pinned));
    assert!(!Arc::ptr_eq(&table.get(duplicated).unwrap(), &replacement));
}

#[test]
fn dup_file_min_limit_publishes_lowest_fd_and_cloexec_together() {
    let table = FdTable::new();
    let pinned = file(3);
    let fd0 = table.alloc(file(4)).unwrap();
    let reserved = table.get_unused_fd_flags(OpenFlags::empty(), 8).unwrap();
    let fd2 = table.alloc(file(5)).unwrap();
    table.close(fd2).unwrap();
    let refs = Arc::strong_count(&pinned);

    let duplicated = table.dup_file_min_limit(&pinned, fd0, true, fd2 as usize + 1).unwrap();
    let installed = table.get(duplicated).unwrap();
    assert_eq!(reserved, 1);
    assert_eq!(duplicated, fd2, "live reservation is not available for duplication");
    assert!(table.cloexec(duplicated).unwrap());
    assert!(Arc::ptr_eq(&installed, &pinned));
    assert_eq!(Arc::strong_count(&pinned), refs + 2, "fd plus temporary get reference");
    let refs_after_install = Arc::strong_count(&pinned);
    assert_eq!(table.dup_file_min_limit(&pinned, -1, false, 8), Err(VfsError::Einval));
    assert_eq!(table.dup_file_min_limit(&pinned, 8, false, 8), Err(VfsError::Einval));
    assert_eq!(Arc::strong_count(&pinned), refs_after_install, "failed duplication adds no reference");
    table.put_unused_fd(reserved);
}
