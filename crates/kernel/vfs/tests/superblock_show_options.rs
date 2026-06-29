//! D39/D3 lock: the `SuperOps` trait (Linux `struct super_operations`) carries
//! the `/proc/mounts`-rendering hooks `show_options`/`show_devname`/`show_path`/
//! `show_stats` AND the writeback hook `dirty_inode`, each with a Linux-faithful
//! DEFAULT so every existing backend compiles unchanged.
//!
//! This exercises BOTH halves:
//!   - a backend that OVERRIDES `show_options` (the tmpfs `size=`/`mode=` lane)
//!     plus `show_devname`/`show_path`, reached verbatim through the SB-level
//!     `SuperBlock::show_options`/`show_devname`/`show_path` passthroughs;
//!   - a backend that overrides NOTHING — the defaults: `show_options() == ""`,
//!     `show_devname()/show_path()/show_stats() == None`, and `dirty_inode`
//!     ORs the requested `I_DIRTY` bits into the inode `i_state` while masking
//!     out a smuggled lifecycle bit (`I_NEW`).

use std::sync::Arc;

use vfs::fs::FileSystem;
use vfs::superblock::next_anon_dev;
use vfs::{
    FileType, Inode, InodeBuilder, KResult, SbStatFs, SuperBlock, SuperOps,
    default_file_ops, default_inode_ops, mk_mode, I_DIRTY, I_NEW,
};

/// A tmpfs-shaped `SuperOps` that publishes its own mount-options tail plus a
/// source-device + mount-path override (the `nfs`/`overlay`-class case).
struct RichOps;
impl SuperOps for RichOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn show_options(&self) -> String { String::from(",size=10240k,nr_inodes=2560,mode=755") }
    fn show_devname(&self) -> Option<String> { Some(String::from("server:/export")) }
    fn show_path(&self) -> Option<String> { Some(String::from("/synthetic/root")) }
    fn show_stats(&self) -> Option<String> { Some(String::from("rpc 1 2 3")) }
}

/// A pseudo-fs `SuperOps` that overrides nothing — every hook takes its default.
struct PlainOps;
impl SuperOps for PlainOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}

struct RichFs;
impl FileSystem for RichFs {
    fn name(&self) -> &str { "richfs" }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(Arc::new(RichOps)) }
}

struct PlainFs;
impl FileSystem for PlainFs {
    fn name(&self) -> &str { "plainfs" }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(Arc::new(PlainOps)) }
}

fn tinode() -> Arc<Inode> {
    InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

/// T-show-options-override: an overriding backend's option tail + devname/path/
/// stats reach userspace verbatim through the SB-level passthroughs.
#[test]
fn sb_show_options_dispatches_to_overridden_s_op() {
    let sb = SuperBlock::for_backend(Arc::new(RichFs), None, next_anon_dev(), String::from("richfs"));
    assert_eq!(sb.show_options(), ",size=10240k,nr_inodes=2560,mode=755");
    assert_eq!(sb.show_devname(), Some(String::from("server:/export")));
    assert_eq!(sb.show_path(), Some(String::from("/synthetic/root")));
    assert_eq!(sb.show_stats(), Some(String::from("rpc 1 2 3")));
}

/// T-show-options-default: a backend overriding nothing gets the Linux defaults
/// — empty options, `None` devname/path/stats.
#[test]
fn sb_show_options_defaults_to_empty_and_none() {
    let sb = SuperBlock::for_backend(Arc::new(PlainFs), None, next_anon_dev(), String::from("plainfs"));
    assert_eq!(sb.show_options(), "");
    assert_eq!(sb.show_devname(), None);
    assert_eq!(sb.show_path(), None);
    assert_eq!(sb.show_stats(), None);
}

/// T-dirty-inode-default: the default `dirty_inode` ORs the requested `I_DIRTY`
/// bits into `i_state` and MASKS OUT a smuggled lifecycle bit (`I_NEW`).
#[test]
fn dirty_inode_default_marks_state_and_masks_lifecycle() {
    let sb = SuperBlock::for_backend(Arc::new(PlainFs), None, next_anon_dev(), String::from("plainfs"));
    let inode = tinode();
    assert_eq!(inode.i_state() & I_DIRTY, 0, "born clean");
    // Try to smuggle I_NEW through the dirtying path alongside the dirty bits.
    sb.dirty_inode(&inode, I_DIRTY | I_NEW);
    assert_eq!(inode.i_state() & I_DIRTY, I_DIRTY, "all I_DIRTY bits set");
    assert_eq!(inode.i_state() & I_NEW, 0, "lifecycle bit masked out, not smuggled in");
}
