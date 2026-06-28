//! vfs-model regression: the registry-driven mount path is `fill_super`.
//! Proves D40 (get_fs_type → FileSystemType::mount), D1 (a fresh
//! `SuperBlock` per mount), D38 (statfs `f_type` IS the sb `s_magic`,
//! no path-prefix table) and D6 (the `s_op->statfs` surface) together:
//! resolve a type by name, mount it twice, and assert two distinct
//! superblocks each report their own magic + a distinct anon `s_dev`.
//!
//! SERIAL: registers/unregisters one unique type name on the global list.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

use vfs::fs::{get_fs_type, register_filesystem, unregister_filesystem};
use vfs::inode::Inode;
use vfs::superblock::{next_anon_dev, FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{FileType, InodeRef, KResult, VfsError};

const RAM_MAGIC: u64 = 0x858458f6; // ramfs (linux/magic.h)

struct RamType;
impl FileSystemType for RamType {
    fn name(&self) -> &str { "t250ram" }
    // `mount` IS fill_super: a fresh SuperBlock with its own anon s_dev.
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> {
        let dev = next_anon_dev();
        let sb = SuperBlock::new(
            Arc::new(RamType), Arc::new(RamOps), RAM_MAGIC, dev, 4096, "t250ram".into(), Arc::new(()),
        );
        let root: InodeRef = Arc::new(RamDir { ino: 2, sb: Arc::downgrade(&sb), kids: Mutex::new(BTreeMap::new()) });
        vfs::d_make_root(root, &sb);
        Ok(sb)
    }
}

struct RamOps;
impl SuperOps for RamOps {
    // Only the magic-bearing surface; counts left 0 (the D6 generic case).
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs { f_type: RAM_MAGIC, f_bsize: 4096, ..Default::default() }) }
}

struct RamDir { ino: u64, sb: Weak<SuperBlock>, kids: Mutex<BTreeMap<String, InodeRef>> }
impl Inode for RamDir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        self.kids.lock().unwrap().get(name).cloned().ok_or(VfsError::Enoent)
    }
}

#[test]
fn registry_mount_is_fill_super_distinct_sb_per_mount() {
    register_filesystem(Arc::new(RamType)).expect("register t250ram");

    let ty = get_fs_type("t250ram").expect("type resolves by name");

    // Two mounts of the SAME type → two distinct superblocks (D1).
    let sb1 = ty.mount("none", "").expect("mount 1 = fill_super");
    let sb2 = ty.mount("none", "").expect("mount 2 = fill_super");
    assert!(!Arc::ptr_eq(&sb1, &sb2), "each mount allocates a fresh SuperBlock");
    assert_ne!(sb1.s_dev, sb2.s_dev, "each mount gets a distinct anon s_dev");

    // statfs f_type IS the sb magic (D38: no path-prefix classifier).
    assert_eq!(sb1.s_magic, RAM_MAGIC);
    assert_eq!(sb1.statfs().unwrap().f_type, RAM_MAGIC, "f_type == s_magic");
    // f_fsid defaults from s_dev when the backend leaves it 0.
    assert_eq!(sb1.statfs().unwrap().f_fsid, sb1.s_dev, "f_fsid defaults from s_dev");

    // Each SB carries a positive, parentless root dentry (d_make_root).
    let root = sb1.s_root().expect("s_root installed by d_make_root");
    assert!(!root.is_negative() && root.parent().is_none());
    assert!(Arc::ptr_eq(&root.d_sb().unwrap(), &sb1), "root.d_sb == its SuperBlock");

    unregister_filesystem("t250ram").expect("cleanup");
}
