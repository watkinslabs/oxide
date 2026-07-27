use std::sync::Arc;
use std::sync::atomic::Ordering;

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{Cred, FileType, InodeBuilder, InodeRef, KResult, VfsError,
    I_LINKABLE, S_APPEND, S_IMMUTABLE, default_file_ops, default_inode_ops, mk_mode};

struct TestFsType;
impl FileSystemType for TestFsType {
    fn name(&self) -> &str { "testfs" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> {
        Ok(test_sb())
    }
}

struct TestSuperOps;
impl SuperOps for TestSuperOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs { f_bsize: 4096, ..Default::default() }) }
}

fn test_sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TestFsType), Arc::new(TestSuperOps), 0x74657374, 1, 4096,
        "testfs".into(), Arc::new(()))
}

fn user(uid: u32) -> Cred {
    Cred { uid, gid: uid, cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty() }
}

fn dir(mode: u16) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Directory, mode), default_inode_ops(),
        default_file_ops()).owner(0, 0).build()
}

fn reg(mode: u16, owner: u32) -> InodeRef {
    InodeBuilder::new(2, mk_mode(FileType::Regular, mode), default_inode_ops(),
        default_file_ops()).owner(owner, owner).build()
}

#[test]
fn protected_hardlink_rejects_non_owner_unsafe_source() {
    let parent = dir(0o777);
    let src = reg(0o4755, 0);
    assert_eq!(vfs::may_link(&parent, &src, &user(1000)), Err(VfsError::Eperm));
}

#[test]
fn protected_hardlink_allows_non_owner_safe_source() {
    let parent = dir(0o777);
    let src = reg(0o666, 0);
    assert_eq!(vfs::may_link(&parent, &src, &user(1000)), Ok(()));
}

#[test]
fn cap_fowner_allows_unsafe_non_owner_source() {
    let parent = dir(0o777);
    let src = reg(0o4755, 0);
    let mut cred = user(1000);
    cred.cap_fowner = true;
    assert_eq!(vfs::may_link(&parent, &src, &cred), Ok(()));
}

#[test]
fn append_and_immutable_sources_are_rejected() {
    let parent = dir(0o777);
    let cred = user(0);
    let append = reg(0o644, 0);
    append.set_i_flags(S_APPEND);
    let immutable = reg(0o644, 0);
    immutable.set_i_flags(S_IMMUTABLE);
    assert_eq!(vfs::may_link(&parent, &append, &cred), Err(VfsError::Eperm));
    assert_eq!(vfs::may_link(&parent, &immutable, &cred), Err(VfsError::Eperm));
}

#[test]
fn unlinked_source_is_enoent() {
    let parent = dir(0o777);
    let src = reg(0o644, 0);
    src.set_nlink(0);
    assert_eq!(vfs::may_link(&parent, &src, &user(0)), Err(VfsError::Enoent));
}

#[test]
fn linkable_tmpfile_source_is_allowed_with_zero_nlink() {
    let parent = dir(0o777);
    let src = reg(0o644, 0);
    src.set_nlink(0);
    src.set_state(I_LINKABLE, 0);
    assert_eq!(vfs::may_link(&parent, &src, &user(0)), Ok(()));
}

#[test]
fn superblock_max_links_is_emlink() {
    let parent = dir(0o777);
    let sb = test_sb();
    sb.s_max_links.store(2, Ordering::Relaxed);
    let src = InodeBuilder::new(3, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(&sb)).owner(0, 0).nlink(2).build();
    assert_eq!(vfs::may_link(&parent, &src, &user(0)), Err(VfsError::Emlink));
}
