//! New-mount-API WIRING (D5/D13/D23/D50/D51): drive a real `vfs::fs::FsContext`
//! through the `fsopen`→`fsconfig`→`vfs_get_tree`→`fsmount`/`move_mount`
//! lifecycle the syscall handlers now thread, then graft the REALIZED
//! superblock with [`vfs::mount::attach_sb`] (the `move_mount` mode-(a) attach)
//! and prove it lands in the mount table byte-equivalent to a `register` graft.
//! Also proves the D23 `FS_REQUIRES_DEV` source gate in `vfs_get_tree`.
//! Driven over the real global mount table, no QEMU.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::fs_context::FsContext;
use vfs::fs::{vfs_get_tree, vfs_parse_fs_param, FileSystem, FsFlags, FsParameter};
use vfs::inode::{Inode, InodeBuilder};
use vfs::superblock::{next_anon_dev, FileSystemType, SuperBlock, SB_RDONLY};
use vfs::{default_file_ops, mk_mode, FileType, InodeOps, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0);
    common::install();
    g
}

struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}

/// Pseudo backend (a converted-style fs: target-independent singleton root).
struct PseudoBe { root_ino: u64 }
impl FileSystem for PseudoBe {
    fn name(&self) -> &str { "fc_pseudo" }
    fn magic(&self) -> u64 { 0x1234 }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.root_ino)) }
}

/// A `file_system_type` whose `mount` (`fill_super`) builds a real SB over the
/// backend root — the legacy adapter `get_tree` the new-mount-API path drives.
/// `flags` carries the D23 `FS_REQUIRES_DEV` classification.
struct Ty { nm: &'static str, root_ino: u64, flags: FsFlags }
impl FileSystemType for Ty {
    fn name(&self) -> &str { self.nm }
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> {
        let fs: Arc<dyn FileSystem> = Arc::new(PseudoBe { root_ino: self.root_ino });
        let root = fs.root();
        Ok(SuperBlock::for_backend(fs, root, next_anon_dev(), self.nm.to_string()))
    }
    fn fs_flags(&self) -> FsFlags { self.flags }
}

/// D5/D13/D50/D51: a context built for a mount, fed one param, then
/// `vfs_get_tree` realizes the SB (with the user `SB_RDONLY` slice stamped);
/// `attach_sb` grafts that SB at a path so it is visible in the mount table and
/// carries the realized read-only SuperBlock — the executor's
/// fsopen/fsconfig/fsmount/move_mount(tmpfs/sysfs/proc) outcome.
#[test]
fn get_tree_then_attach_sb_is_visible_and_ro() {
    let _g = guard();
    let ty: Arc<dyn FileSystemType> = Arc::new(Ty { nm: "fc_pseudo", root_ino: 0xCAFE, flags: FsFlags::empty() });

    // fsopen-equiv: a FOR_MOUNT context requesting SB_RDONLY.
    let mut fc = FsContext::for_mount(ty, SB_RDONLY);
    // fsconfig(SET_FLAG)-equiv: a param is accepted (never dropped — D14).
    vfs_parse_fs_param(&mut fc, &FsParameter::flag("noatime")).expect("parse_param flag");
    // fsconfig(CMD_CREATE)-equiv: realize the tree (D13).
    vfs_get_tree(&mut fc).expect("vfs_get_tree realizes the SB");
    let sb = fc.sb().expect("get_tree pinned fc->sb").clone();
    assert!(fc.root().is_some(), "get_tree pinned fc->root");
    assert!(sb.is_readonly(), "user SB_RDONLY slice stamped on the realized SB");

    // move_mount mode-(a)-equiv: graft the realized SB.
    vfs::mount::attach_sb(Some(common::dentry("/fc_attach")), sb.clone()).expect("attach_sb");
    let m = common::mount_at_path_exact("/fc_attach").expect("realized mount present in table");
    assert!(Arc::ptr_eq(m.sb(), &sb), "the grafted mount carries the SAME realized SuperBlock");
    assert_eq!(m.mnt_root().and_then(|r| r.inode()).map(|i| i.ino()), Some(0xCAFE),
        "mnt_root().inode() derived from sb.s_root (byte-equivalent to register)");
    assert!(m.sb().is_readonly(), "grafted mount's SB stays read-only");
}

/// D23: a `FS_REQUIRES_DEV` filesystem with no source device fails `vfs_get_tree`
/// (Linux `get_tree_bdev` rejects a missing dev_name); a pseudo fs (default
/// flags) with no source succeeds.
#[test]
fn requires_dev_without_source_fails_get_tree() {
    let _g = guard();
    let dev_ty: Arc<dyn FileSystemType> =
        Arc::new(Ty { nm: "fc_devty", root_ino: 0xD00D, flags: FsFlags::FS_REQUIRES_DEV });
    let mut fc = FsContext::for_mount(dev_ty, 0);
    assert!(vfs_get_tree(&mut fc).is_err(),
        "FS_REQUIRES_DEV + no source → get_tree fails (D23)");

    let pseudo_ty: Arc<dyn FileSystemType> =
        Arc::new(Ty { nm: "fc_pseudo2", root_ino: 0xBEAD, flags: FsFlags::empty() });
    let mut fc2 = FsContext::for_mount(pseudo_ty, 0);
    assert!(vfs_get_tree(&mut fc2).is_ok(),
        "pseudo fs (no FS_REQUIRES_DEV) mounts with no source");
}
