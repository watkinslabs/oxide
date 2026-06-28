//! `current_time` / `inode_set_ctime_current` (Linux fs/inode.c): the candidate
//! wall-clock timestamp is floored to the inode's superblock `s_time_gran`
//! before it is stamped, so no sub-granularity precision is recorded. An
//! SB-less inode keeps full ns precision. Reuses `SuperBlock::timestamp_truncate`
//! (no duplicate rounding math).

use std::sync::Arc;

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::inode_times::{current_time, inode_set_ctime_current};
use vfs::superblock::NSEC_PER_SEC;
use vfs::{FileType, InodeRef, KResult, SuperBlock, VfsError};

/// Backend with a name only — the test exercises SB granularity, not storage.
struct TFs;
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
}

fn sb_with_gran(gran: u32) -> Arc<SuperBlock> {
    let sb = SuperBlock::for_backend(Arc::new(TFs), None, 0x77, String::from("tfs"));
    sb.set_time_gran(gran);
    sb
}

/// Regular-file inode that reports a given owning superblock (or none).
struct TNode { sb: Option<Arc<SuperBlock>> }
impl Inode for TNode {
    fn ino(&self) -> vfs::Ino { 1 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.clone() }
}

#[test]
fn coarse_gran_floors_subsecond() {
    let node = TNode { sb: Some(sb_with_gran(1_000_000)) }; // 1 ms
    let t = 7 * NSEC_PER_SEC + 123_456_789;
    // 123_456_789 ns floored to a 1 ms (1_000_000 ns) multiple = 123_000_000.
    assert_eq!(current_time(&node, t), 7 * NSEC_PER_SEC + 123_000_000);
}

#[test]
fn ns_gran_is_identity() {
    let node = TNode { sb: Some(sb_with_gran(1)) }; // ns precision
    let t = 9 * NSEC_PER_SEC + 42;
    assert_eq!(current_time(&node, t), t);
}

#[test]
fn sb_less_inode_keeps_full_precision() {
    let node = TNode { sb: None };
    let t = 3 * NSEC_PER_SEC + 999;
    assert_eq!(current_time(&node, t), t, "anon inode has no s_time_gran to floor to");
}

#[test]
fn set_ctime_current_returns_floored_value() {
    let node: InodeRef = Arc::new(TNode { sb: Some(sb_with_gran(1_000)) }); // 1 µs
    let t = 5 * NSEC_PER_SEC + 654_321;
    // Stamp + report: the returned ctime equals current_time (floored to µs).
    assert_eq!(inode_set_ctime_current(&node, t), 5 * NSEC_PER_SEC + 654_000);
}
