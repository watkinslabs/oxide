//! show_options: `FileSystem::show_options()` is the per-instance
//! `super_operations::show_options` (Linux `fs/*/super.c`). The VFS renders the
//! generic per-mount flags (`rw,relatime`) for `/proc/mounts`; this hook APPENDS
//! the backend's own options (tmpfs `size=`/`mode=`, ext4 `data=`, cgroup2
//! controller list). Each option carries its own leading comma, concatenated
//! directly after the generic flags; `/proc/mounts` owns the generic line
//! framing from mount + superblock state, not a backend string hook.

use std::sync::Arc;

mod common;

use vfs::fs::FileSystem;
use vfs::superblock::next_anon_dev;
use vfs::{
    FileType, InodeBuilder, InodeRef, KResult, SbStatFs, SuperOps,
    default_file_ops, default_inode_ops, mk_mode,
};

fn tdir() -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Directory, 0), default_inode_ops(), default_file_ops()).build()
}

/// A backend with no `show_options` override ⇒ no fs-specific options.
struct PlainFs;
impl FileSystem for PlainFs {
    fn name(&self) -> &str { "ext4" }
    fn root(&self) -> Option<InodeRef> { Some(tdir()) }
}

/// A tmpfs-shaped backend that publishes `size=`/`nr_inodes=`/`mode=` like
/// Linux `shmem_show_options` — each option comma-prefixed.
struct TmpFs;
impl FileSystem for TmpFs {
    fn name(&self) -> &str { "tmpfs" }
    fn root(&self) -> Option<InodeRef> { Some(tdir()) }
    fn show_options(&self) -> String {
        String::from(",size=10240k,nr_inodes=2560,mode=755")
    }
}

#[test]
fn default_show_options_is_empty() {
    // No override ⇒ no fs-specific tail; the generic flags stand alone.
    assert_eq!(PlainFs.show_options(), "");
}

#[test]
fn backend_show_options_survives_fill_super() {
    let sb = common::realize_sb(
        Arc::new(TmpFs), None, next_anon_dev(), String::from("tmpfs"));
    assert_eq!(sb.show_options(), ",size=10240k,nr_inodes=2560,mode=755",
        "constructor-era show_options is snapshotted into s_op, not a mounts-line formatter");
}

/// D39/D3 consumer wiring: a backend whose `s_op->show_options` (SuperOps) is
/// overridden surfaces THAT tail in the mounts line when the SuperBlock is
/// threaded in (`mnt.sb()`), NOT the FileSystem-level `show_options`.
struct SbRichOps;
impl SuperOps for SbRichOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn show_options(&self) -> String { String::from(",size=20480k,mode=1777") }
}

/// A backend whose SuperOps publishes options but whose FileSystem-level
/// `show_options` deliberately differs — proving the SB path is the source.
struct SbRichFs;
impl FileSystem for SbRichFs {
    fn name(&self) -> &str { "sbrichfs" }
    fn root(&self) -> Option<InodeRef> { Some(tdir()) }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(Arc::new(SbRichOps)) }
    // Distinct from the SuperOps tail so a regression that reads this instead
    // of the SB would be caught by the assert below.
    fn show_options(&self) -> String { String::from(",WRONG-fs-level") }
}

#[test]
fn superblock_routes_options_through_s_op() {
    let sb = common::realize_sb(
        Arc::new(SbRichFs), None, next_anon_dev(), String::from("sbrichfs"));
    assert_eq!(sb.show_options(), ",size=20480k,mode=1777",
        "s_op->show_options tail wins; mounted SB has no backend-line fallback");
}
