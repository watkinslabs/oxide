//! B4 (ext4fix §5.2): orphan cleanup RESUMES an interrupted truncate. A crash
//! mid-truncate leaves the inode on the orphan list with nlink>0, i_size at the
//! truncate target, but the blocks past i_size not yet freed. Mount-time
//! `orphan_cleanup` must truncate it to i_size (reclaiming the leaked blocks),
//! not merely splice it off the list. Image: mini-j.img (journaled).

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const ROOT: u32 = 2;

fn shared_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

#[test]
fn mount_cleanup_resumes_interrupted_truncate() {
    let disk = shared_disk();
    let m = ext4::Mount::open(disk.clone()).expect("mount");
    let bs = m.sb.block_size as u64;

    // Create an 8-block file.
    let ino = m.create_file(ROOT, b"trunc", 0o644, 0, 0).expect("create");
    let data = alloc::vec![0xABu8; (8 * bs) as usize];
    m.write_at(ino, 0, &data).expect("write 8 blocks");
    let i_blocks_full = m.read_inode(ino).unwrap().i_blocks;
    assert!(i_blocks_full >= 8 * (bs / 512), "8 data blocks allocated");

    // Simulate a crash mid-truncate: i_size dropped to 2 blocks, but the 8
    // blocks are STILL allocated (the truncate hadn't freed 2..8 yet), and the
    // inode is parked on the orphan list.
    m.set_inode_size(ino, 2 * bs).expect("shrink i_size only");
    m.orphan_add(ino).expect("orphan_add");

    let free_before = m.state_free_blocks();
    assert_ne!(m.read_sb_last_orphan().unwrap(), 0, "orphan list non-empty pre-cleanup");

    // Remount → Mount::open runs orphan_cleanup → resumes the truncate.
    drop(m);
    let m2 = ext4::Mount::open(disk).expect("remount runs orphan_cleanup");

    // The leaked blocks (2..8) are reclaimed, the inode is off the orphan list,
    // and the file still exists (it was linked, nlink>0).
    let i_blocks_after = m2.read_inode(ino).unwrap().i_blocks;
    assert!(i_blocks_after < i_blocks_full, "blocks past i_size were freed");
    assert!(m2.state_free_blocks() > free_before, "free-block count rose (leak reclaimed)");
    assert_eq!(m2.read_sb_last_orphan().unwrap(), 0, "orphan list drained");
    assert!(m2.lookup_path(b"/trunc").is_ok(), "linked file still present");
    assert_eq!(m2.read_inode(ino).unwrap().size, 2 * bs, "i_size unchanged (truncate target)");
}
