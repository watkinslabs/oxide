//! vfs-model regression: the registry-driven mount path is `fill_super`.
//! Proves D40 (get_fs_type → FileSystemType::mount), D1 (a fresh
//! `SuperBlock` per mount), D38 (statfs `f_type` IS the sb `s_magic`,
//! no path-prefix table) and D6 (the `s_op->statfs` surface) together:
//! resolve a type by name, mount it twice, and assert two distinct
//! superblocks each report their own magic + a distinct anon `s_dev`.
//!
//! SERIAL: registers/unregisters one unique type name on the global list.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use vfs::fs::{get_fs_type, register_filesystem, unregister_filesystem};
use vfs::superblock::{next_anon_dev, FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError,
          default_file_ops, mk_mode};

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
        let root: InodeRef = ram_dir(2, &sb);
        vfs::d_make_root(root, &sb);
        Ok(sb)
    }
}

struct RamOps;
impl SuperOps for RamOps {
    // Only the magic-bearing surface; counts left 0 (the D6 generic case).
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs { f_type: RAM_MAGIC, f_bsize: 4096, ..Default::default() }) }
}

/// Per-inode directory state (Linux `i_private`): the child table.
struct RamDirData { kids: Mutex<BTreeMap<String, InodeRef>> }

/// Shared `i_op` resolving a name in the directory's `i_private` child table.
struct RamDirOps;
impl InodeOps for RamDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<RamDirData>().unwrap();
        d.kids.lock().unwrap().get(name).cloned().ok_or(VfsError::Enoent)
    }
}

fn ram_dir(ino: u64, sb: &Arc<SuperBlock>) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0), Arc::new(RamDirOps), default_file_ops())
        .sb(Arc::downgrade(sb))
        .private(Arc::new(RamDirData { kids: Mutex::new(BTreeMap::new()) }))
        .build()
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
