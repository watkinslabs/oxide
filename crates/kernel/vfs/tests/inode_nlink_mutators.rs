//! inode `i_nlink` mutators (Linux fs/inode.c `set_nlink`/`inc_nlink`/
//! `drop_nlink`). The authoritative `i_nlink` lives icache-side in the owning
//! superblock's inode cache: seeded from the built inode's `nlink()` when the
//! slot is built, then mutated by these three ops. The load-bearing observable
//! is the drop-to-zero predicate — `i_nlink == 0` is Linux's "no names left →
//! evict on last `iput`" flag (`i_nlink_zero`).

use std::sync::Arc;

use vfs::fs::FileSystem;
use vfs::inode::InodeBuilder;
use vfs::superblock::next_anon_dev;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeRef, SuperBlock};

struct NlinkFs;
impl FileSystem for NlinkFs {
    fn name(&self) -> &str { "nlinkfs" }
    fn magic(&self) -> u64 { 0x6E11 }
}

/// Directory inode reporting Linux's baseline `nlink == 2` (`.` + parent entry,
/// the `InodeBuilder` default for a directory).
fn dir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), default_inode_ops(), default_file_ops()).build()
}

/// Regular file inode reporting `nlink == 1` (the builder default).
fn reg(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::for_backend(Arc::new(NlinkFs), None, next_anon_dev(), String::from("nlinkfs"))
}

#[test]
fn icache_seeds_nlink_from_built_inode() {
    let sb = sb();
    // Uncached ino has no stored count.
    assert_eq!(sb.i_nlink(7), None, "uncached inode has no stored link count");
    // iget seeds the slot from the built inode's `nlink()`: dir=2, regular=1.
    let _d: InodeRef = sb.iget(7, || dir(7));
    let _r: InodeRef = sb.iget(8, || reg(8));
    assert_eq!(sb.i_nlink(7), Some(2), "directory seeds nlink=2 (. + parent)");
    assert_eq!(sb.i_nlink(8), Some(1), "regular file seeds nlink=1");
}

#[test]
fn set_inc_drop_nlink_maintain_stored_count() {
    let sb = sb();
    let _r: InodeRef = sb.iget(8, || reg(8));
    assert_eq!(sb.i_nlink(8), Some(1));

    // link(2): a second hard link.
    sb.inc_nlink(8);
    assert_eq!(sb.i_nlink(8), Some(2), "inc_nlink adds a link");
    assert!(!sb.i_nlink_zero(8), "two links → not an evict candidate");

    // set_nlink installs an explicit count (e.g. ext4 reading on-disk i_links).
    sb.set_nlink(8, 5);
    assert_eq!(sb.i_nlink(8), Some(5), "set_nlink installs the explicit count");

    // unlink(2) of each name back down.
    sb.set_nlink(8, 2);
    sb.drop_nlink(8);
    assert_eq!(sb.i_nlink(8), Some(1), "drop_nlink removes a link");
    assert!(!sb.i_nlink_zero(8), "one link remaining → still live");
}

#[test]
fn drop_to_zero_is_the_evict_predicate() {
    let sb = sb();
    let _r: InodeRef = sb.iget(8, || reg(8));
    // Last name removed: drop 1 → 0 makes it an eviction candidate.
    sb.drop_nlink(8);
    assert_eq!(sb.i_nlink(8), Some(0), "last link dropped");
    assert!(sb.i_nlink_zero(8), "i_nlink==0 → candidate for evict on last iput");
}

#[test]
fn drop_saturates_at_zero_and_set_revives() {
    let sb = sb();
    let _r: InodeRef = sb.iget(8, || reg(8));
    sb.drop_nlink(8);
    sb.drop_nlink(8); // already 0 — must saturate, never underflow-wrap to u32::MAX
    assert_eq!(sb.i_nlink(8), Some(0), "drop_nlink saturates at zero");
    // A filesystem may revive a 0-count inode (0 → 1); inc + set both express it.
    sb.set_nlink(8, 0); // clear_nlink path
    assert!(sb.i_nlink_zero(8));
    sb.inc_nlink(8);
    assert_eq!(sb.i_nlink(8), Some(1), "inc_nlink revives a zero-count inode");
    assert!(!sb.i_nlink_zero(8), "revived inode no longer an evict candidate");
}

#[test]
fn mutators_are_noop_on_uncached_ino() {
    let sb = sb();
    // No slot for ino 99 → every mutator is a silent no-op (Linux operates on a
    // live `struct inode`; an uncached ino has none).
    sb.set_nlink(99, 4);
    sb.inc_nlink(99);
    sb.drop_nlink(99);
    assert_eq!(sb.i_nlink(99), None, "uncached ino never gains a stored count");
    assert!(!sb.i_nlink_zero(99), "uncached ino is not an evict candidate");
}
