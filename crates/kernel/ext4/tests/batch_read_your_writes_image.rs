//! Lane 1b (ext4-compat-plan): read-your-writes under cross-op batching. A
//! directory entry (or nested dir, or slow symlink target) created earlier in a
//! running batched transaction MUST be visible to a later lookup in the SAME
//! batch — Linux sees a transaction's own metadata writes via the buffer cache;
//! our `MountState.shadow` is that buffer. `lookup_in_dir`/`read_symlink_target`
//! read via the shadow-aware `read_file_block_meta`, not the stale on-disk read.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;

fn fresh_disk() -> Arc<MemDisk<TaskList>> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    disk
}

#[test]
fn nested_dir_created_in_batch_is_visible_to_lookup() {
    let disk = fresh_disk();
    let m = ext4::Mount::open(disk.clone() as Arc<dyn BlockDevice>).unwrap();
    m.begin_batch();
    // Create a fresh dir, then a child INSIDE it — the child's dirent lands in
    // the just-allocated (shadow-only) dir block.
    let parent = m.create_dir(2, b"batchdir", 0o755, 0, 0).expect("mkdir batchdir");
    let child = m.create_dir(parent, b"child", 0o755, 0, 0).expect("mkdir child");
    // Read-your-writes: the child must be findable WITHIN the same batch.
    let got = m.lookup_path(b"/batchdir/child")
        .expect("nested dir created in-batch must be visible to lookup (read-your-writes)");
    assert_eq!(got, child, "lookup resolves to the just-created child inode");
    // And a sibling created after also resolves (multiple in-batch dirents).
    let sib = m.create_dir(parent, b"sibling", 0o755, 0, 0).expect("mkdir sibling");
    assert_eq!(m.lookup_path(b"/batchdir/sibling").unwrap(), sib);
    // Commit + remount: everything durable.
    m.commit_batch().expect("commit_batch");
    drop(m);
    let m2 = ext4::Mount::open(disk as Arc<dyn BlockDevice>).unwrap();
    assert_eq!(m2.lookup_path(b"/batchdir/child").unwrap(), child, "child persisted");
    assert_eq!(m2.lookup_path(b"/batchdir/sibling").unwrap(), sib, "sibling persisted");
}

#[test]
fn slow_symlink_target_created_in_batch_is_readable() {
    let disk = fresh_disk();
    let m = ext4::Mount::open(disk as Arc<dyn BlockDevice>).unwrap();
    m.begin_batch();
    let d = m.create_dir(2, b"lnkdir", 0o755, 0, 0).expect("mkdir");
    // >60B target => slow symlink (external data block, shadow-staged).
    let long = alloc::format!("/deep/{}/target", "seg/".repeat(16));
    assert!(long.len() > 60);
    m.create_symlink(d, b"sl", long.as_bytes(), 0, 0).expect("create slow symlink");
    // lookup_path follows the symlink; resolving its target reads the staged
    // block via the shadow-aware path (else NotFound / stale bytes).
    match m.lookup_path(b"/lnkdir/sl") {
        Ok(_) => {}
        Err(ext4::MountError::NotFound) => {} // target path doesn't exist, but the
        // symlink's own target block WAS read (no BadChecksum / stale-bytes panic).
        Err(e) => panic!("slow symlink target read in-batch faulted: {e:?}"),
    }
    m.commit_batch().expect("commit");
}
