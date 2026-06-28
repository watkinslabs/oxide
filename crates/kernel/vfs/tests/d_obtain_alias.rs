//! dcache-D29: `d_obtain_alias` + `DCACHE_DISCONNECTED` (Linux fs/dcache.c).
//! A dentry referring to an inode WITHOUT a path/parent — reusing an existing
//! alias (mandatory for directories) or allocating a new anonymous dentry on
//! `s_anon`. Driven against a real ramfs SuperBlock so `i_sb()` resolves and
//! the `i_dentry` alias list works.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

use vfs::dcache::d_obtain_alias;
use vfs::dentry::D_DISCONNECTED;
use vfs::inode::Inode;
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{Dentry, FileType, InodeRef, KResult, VfsError};

struct RamFsType;
impl FileSystemType for RamFsType {
    fn name(&self) -> &str { "ramfs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Ok(mount_ramfs(0x51)) }
}
struct RamFsOps;
impl SuperOps for RamFsOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs { f_bsize: 4096, ..Default::default() }) }
}

struct RamDir { ino: u64, sb: Weak<SuperBlock>, kids: Mutex<BTreeMap<String, InodeRef>> }
impl Inode for RamDir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, n: &str) -> KResult<InodeRef> { self.kids.lock().unwrap().get(n).cloned().ok_or(VfsError::Enoent) }
}
struct RamFile { ino: u64, sb: Weak<SuperBlock> }
impl Inode for RamFile {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

fn ramdir(sb: &Arc<SuperBlock>, ino: u64) -> Arc<RamDir> {
    Arc::new(RamDir { ino, sb: Arc::downgrade(sb), kids: Mutex::new(BTreeMap::new()) })
}
fn ramfile(sb: &Arc<SuperBlock>, ino: u64) -> InodeRef { Arc::new(RamFile { ino, sb: Arc::downgrade(sb) }) }

fn mount_ramfs(s_dev: u64) -> Arc<SuperBlock> {
    let sb = SuperBlock::new(Arc::new(RamFsType), Arc::new(RamFsOps), 0x858458f6, s_dev, 4096, "ramfs".into(), Arc::new(()));
    vfs::d_make_root(ramdir(&sb, 2), &sb);
    sb
}

// Fresh inode with NO alias → a new anonymous disconnected dentry, now on the
// inode's i_dentry alias list.
#[test]
fn obtain_alias_fresh_inode_is_disconnected_parentless() {
    let sb = mount_ramfs(1);
    let inode = sb.iget(11, || ramfile(&sb, 11));
    assert_eq!(sb.i_aliases(11).len(), 0, "no alias before d_obtain_alias");

    let anon = d_obtain_alias(inode.clone());
    assert!(Arc::ptr_eq(&anon.inode().unwrap(), &inode), "anon dentry refers to the inode");
    assert!(anon.is_disconnected(), "D_DISCONNECTED set");
    assert_ne!(anon.flags() & D_DISCONNECTED, 0);
    assert!(anon.parent().is_none(), "anon dentry is parentless");
    assert!(!anon.is_root(), "anon dentry is NOT a superblock root");

    // Recorded on the inode's alias list via the shared i_add_alias path.
    let aliases = sb.i_aliases(11);
    assert_eq!(aliases.len(), 1, "anon dentry recorded as the inode's alias");
    assert!(Arc::ptr_eq(&aliases[0], &anon));
}

// Directory inode that ALREADY has an alias → REUSE that exact dentry
// (Arc::ptr_eq), never a second dir dentry.
#[test]
fn obtain_alias_reuses_existing_directory_alias() {
    let sb = mount_ramfs(2);
    let dino: InodeRef = ramdir(&sb, 30);
    // Give it an existing alias under a parent (the d_add path records it).
    let root = sb.s_root().unwrap();
    let existing = vfs::d_add(&root, "d", dino.clone());
    assert_eq!(sb.i_aliases(30).len(), 1);

    let got = d_obtain_alias(dino.clone());
    assert!(Arc::ptr_eq(&got, &existing), "directory: reuse the one existing alias");
    assert_eq!(sb.i_aliases(30).len(), 1, "no second dentry created for the dir");
}

// Reuse also holds when the existing alias is itself an anon dentry: a second
// d_obtain_alias returns the SAME anon dentry.
#[test]
fn obtain_alias_idempotent_on_anon() {
    let sb = mount_ramfs(3);
    let inode = sb.iget(40, || ramfile(&sb, 40));
    let a1 = d_obtain_alias(inode.clone());
    let a2 = d_obtain_alias(inode.clone());
    assert!(Arc::ptr_eq(&a1, &a2), "second call reuses the anon alias");
    assert_eq!(sb.i_aliases(40).len(), 1, "still a single alias");
}

// An sb-less inode still yields a valid anon dentry (alias just unrecorded).
#[test]
fn obtain_alias_sbless_inode_graceful() {
    struct Bare;
    impl Inode for Bare {
        fn ino(&self) -> vfs::Ino { 99 }
        fn file_type(&self) -> FileType { FileType::Regular }
        fn size(&self) -> u64 { 0 }
        fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    }
    let inode: InodeRef = Arc::new(Bare);
    let anon: Arc<Dentry> = d_obtain_alias(inode.clone());
    assert!(anon.is_disconnected());
    assert!(anon.parent().is_none());
    assert!(Arc::ptr_eq(&anon.inode().unwrap(), &inode));
}
