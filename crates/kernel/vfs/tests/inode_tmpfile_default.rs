//! inode-D24: `i_op->tmpfile` (open(O_TMPFILE)). The trait default is
//! `Eopnotsupp` (Linux `do_tmpfile` errno for a fs without the op) so backends
//! compile unchanged; only a directory backend that overrides it supports
//! O_TMPFILE. This pins the default body + the `Inode::tmpfile` delegator.

use vfs::{CreateCtx, FileType, InodeBuilder, VfsError, default_file_ops, default_inode_ops, mk_mode};

#[test]
fn default_tmpfile_is_eopnotsupp() {
    let i = InodeBuilder::new(1, mk_mode(FileType::Directory, 0o755), default_inode_ops(), default_file_ops())
        .build();
    assert!(matches!(i.tmpfile(0o644, &CreateCtx::root()), Err(VfsError::Eopnotsupp)));
}
