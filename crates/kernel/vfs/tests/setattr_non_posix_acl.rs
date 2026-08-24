//! Generic setattr must not make POSIX-ACL policy decisions for a filesystem
//! that does not advertise POSIX ACL support. Character devices use this path
//! in devtmpfs, where systemd must be able to chmod the node without an
//! `EOPNOTSUPP` from an unrelated ACL lookup.

use std::sync::Arc;

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::setattr::{notify_change, Iattr, ATTR_MODE};
use vfs::posix_acl::AclType;
use vfs::{default_file_ops, default_inode_ops, mk_mode, Cred, FileType, Idmap, InodeBuilder, VfsError};

struct TestType;
impl FileSystemType for TestType {
    fn name(&self) -> &str { "setattr-no-acl" }
    fn mount(&self, _source: Option<&str>, _options: &str) -> vfs::KResult<Arc<SuperBlock>> {
        unreachable!()
    }
}

struct TestOps;
impl SuperOps for TestOps {
    fn statfs(&self) -> vfs::KResult<SbStatFs> { Ok(SbStatFs::default()) }
}

#[test]
fn default_setattr_chmod_succeeds_without_posix_acl_support() {
    let sb = SuperBlock::new(Arc::new(TestType), Arc::new(TestOps), 0, 0xB2629, 4096,
                              "setattr-no-acl".into(), Arc::new(()));
    assert!(!sb.is_posixacl());
    let inode = InodeBuilder::new(1, mk_mode(FileType::CharDev, 0o600), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(&sb)).build();
    let mut ia = Iattr { valid: ATTR_MODE, mode: 0o660, ..Default::default() };
    assert_eq!(notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()), Ok(()));
    assert_eq!(inode.perm(), Some(0o660));
}

#[test]
fn unsupported_acl_lookup_remains_an_explicit_error() {
    let sb = SuperBlock::new(Arc::new(TestType), Arc::new(TestOps), 0, 0xB262A, 4096,
                              "setattr-no-acl".into(), Arc::new(()));
    let inode = InodeBuilder::new(2, mk_mode(FileType::CharDev, 0o600), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(&sb)).build();
    assert_eq!(inode.get_inode_acl(AclType::Access), Err(VfsError::Eopnotsupp));
}
