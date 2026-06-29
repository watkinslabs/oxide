//! fsimpls D11: on-disk orphan list (s_last_orphan + i_dtime NEXT_ORPHAN
//! chaining) — ext4_orphan_add / _del / _cleanup against mini.img.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).unwrap();
    disk
}

// i_dtime / NEXT_ORPHAN offset within an inode slot.
const I_OFF_DTIME: usize = 0x14;

fn read_next_orphan(m: &ext4::Mount, ino: u32) -> u32 {
    let (bytes, _off) = m.read_inode_bytes(ino).unwrap();
    u32::from_le_bytes([bytes[I_OFF_DTIME], bytes[I_OFF_DTIME + 1],
                        bytes[I_OFF_DTIME + 2], bytes[I_OFF_DTIME + 3]])
}

#[test]
fn create_anonymous_adds_to_on_disk_orphan_list() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    assert_eq!(m.read_sb_last_orphan().unwrap(), 0, "clean fs: empty list");
    let a = m.create_anonymous(2, 0o600).unwrap();
    assert_eq!(m.read_sb_last_orphan().unwrap(), a, "head points at the new orphan");
    assert_eq!(read_next_orphan(&m, a), 0, "first orphan chains to 0 (list end)");
}

#[test]
fn second_orphan_chains_to_first() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let a = m.create_anonymous(2, 0o600).unwrap();
    let b = m.create_anonymous(2, 0o600).unwrap();
    assert_eq!(m.read_sb_last_orphan().unwrap(), b, "head is the most-recent orphan");
    assert_eq!(read_next_orphan(&m, b), a, "b chains to a");
    assert_eq!(read_next_orphan(&m, a), 0, "a is the list tail");
}

#[test]
fn orphan_del_splices_middle() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let a = m.create_anonymous(2, 0o600).unwrap();
    let b = m.create_anonymous(2, 0o600).unwrap();
    let c = m.create_anonymous(2, 0o600).unwrap();
    // List head→…: c -> b -> a -> 0. Remove the middle (b).
    m.orphan_del(b).unwrap();
    assert_eq!(m.read_sb_last_orphan().unwrap(), c, "head unchanged");
    assert_eq!(read_next_orphan(&m, c), a, "c now chains past b to a");
    assert_eq!(read_next_orphan(&m, a), 0, "tail intact");
}

#[test]
fn orphan_del_head_advances_sb() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let a = m.create_anonymous(2, 0o600).unwrap();
    let b = m.create_anonymous(2, 0o600).unwrap();
    m.orphan_del(b).unwrap(); // b is the head
    assert_eq!(m.read_sb_last_orphan().unwrap(), a, "head advanced to a");
}

#[test]
fn free_orphan_removes_from_list() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let pre_inodes = m.state_free_inodes();
    let a = m.create_anonymous(2, 0o600).unwrap();
    assert_eq!(m.read_sb_last_orphan().unwrap(), a);
    m.free_orphan_inode(a).unwrap();
    assert_eq!(m.read_sb_last_orphan().unwrap(), 0, "list empty after free");
    assert_eq!(m.state_free_inodes(), pre_inodes, "inode returned to pool");
}

#[test]
fn mount_time_cleanup_reclaims_leaked_orphan() {
    // Simulate a crash: create an O_TMPFILE orphan (nlink=0, on the list)
    // and never free it, then re-mount the SAME disk. orphan_cleanup must
    // reclaim it and empty the list.
    let disk = build_disk();
    let leaked;
    let pre_inodes;
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        pre_inodes = m.state_free_inodes();
        leaked = m.create_anonymous(2, 0o600).unwrap();
        // Give it a data block so cleanup must also free blocks.
        let bs = m.sb.block_size as usize;
        m.append_block(leaked, &std::vec![0u8; bs]).unwrap();
        assert_eq!(m.read_sb_last_orphan().unwrap(), leaked);
        assert!(m.state_free_inodes() < pre_inodes, "inode consumed");
    }
    // Re-mount: Mount::open runs orphan_cleanup.
    let m2 = ext4::Mount::open(disk).unwrap();
    assert_eq!(m2.read_sb_last_orphan().unwrap(), 0, "cleanup emptied the list");
    assert_eq!(m2.state_free_inodes(), pre_inodes, "leaked inode reclaimed");
}
