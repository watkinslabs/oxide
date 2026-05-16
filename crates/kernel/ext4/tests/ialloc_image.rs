//! P7b-04 integration: create_file + unlink against mini.img.

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

#[test]
fn create_file_visible_to_lookup() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"newfile", 0o644).unwrap();
    let got = m.lookup_path(b"/newfile").unwrap();
    assert_eq!(got, n);
    let inode = m.read_inode(n).unwrap();
    assert!(inode.is_reg());
    assert_eq!(inode.size, 0);
    assert_eq!(inode.links_count, 1);
}

#[test]
fn create_then_append_then_read() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"data.bin", 0o644).unwrap();
    let bs = m.sb.block_size as usize;
    let payload: std::vec::Vec<u8> = (0..bs).map(|i| (i & 0xFF) as u8).collect();
    m.append_block(n, &payload).unwrap();
    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.size, bs as u64);
    let blk = m.read_file_block(&inode, 0).unwrap();
    assert_eq!(blk, payload);
}

#[test]
fn unlink_frees_inode_and_blocks() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let pre_blocks = m.state_free_blocks();
    let pre_inodes = m.state_free_inodes();
    let n = m.create_file(2, b"toremove", 0o644).unwrap();
    let bs = m.sb.block_size as usize;
    m.append_block(n, &std::vec![0u8; bs]).unwrap();
    m.append_block(n, &std::vec![0u8; bs]).unwrap();
    m.unlink(2, b"toremove").unwrap();
    assert_eq!(m.state_free_blocks(), pre_blocks, "data blocks returned to pool");
    assert_eq!(m.state_free_inodes(), pre_inodes, "inode returned to pool");
    assert!(m.lookup_path(b"/toremove").is_err());
}

#[test]
fn create_symlink_fast_inline_target() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let target: &[u8] = b"/etc/passwd";
    let n = m.create_symlink(2, b"shortlink", target).unwrap();
    let got = m.lookup_path(b"/shortlink").unwrap();
    assert_eq!(got, n);
    let inode = m.read_inode(n).unwrap();
    assert!(inode.is_link());
    assert_eq!(inode.size, target.len() as u64);
    assert_eq!(inode.links_count, 1);
    assert_eq!(inode.fast_symlink_target(), Some(target));
}

#[test]
fn create_symlink_slow_via_data_block() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    // 80 B target ⇒ > I_BLOCK_LEN(60), forces slow path.
    let target: std::vec::Vec<u8> = (0..80).map(|i| b'A' + ((i % 26) as u8)).collect();
    let n = m.create_symlink(2, b"longlink", &target).unwrap();
    let inode = m.read_inode(n).unwrap();
    assert!(inode.is_link());
    assert_eq!(inode.size, target.len() as u64);
    assert!(inode.fast_symlink_target().is_none());
    let blk = m.read_file_block(&inode, 0).unwrap();
    assert_eq!(&blk[..target.len()], &target[..]);
}

#[test]
fn create_mknod_char_device_persists_rdev() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    // /dev/null encoded as makedev(1,3) ⇒ small-dev = (major<<8) | minor.
    let rdev: u32 = (1u32 << 8) | 3;
    let n = m.create_mknod(2, b"nullnode", 0x2000 | 0o666, rdev).unwrap();
    let got = m.lookup_path(b"/nullnode").unwrap();
    assert_eq!(got, n);
    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.mode & 0xF000, 0x2000); // S_IFCHR
    assert_eq!(inode.size, 0);
    let stored = u32::from_le_bytes([inode.i_block[0], inode.i_block[1], inode.i_block[2], inode.i_block[3]]);
    assert_eq!(stored, rdev);
}

#[test]
fn create_mknod_fifo_no_rdev() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_mknod(2, b"myfifo", 0x1000 | 0o644, 0).unwrap();
    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.mode & 0xF000, 0x1000); // S_IFIFO
    assert_eq!(inode.links_count, 1);
}

#[test]
fn create_mknod_rejects_bad_type() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    // mode = S_IFREG should not be accepted by mknod() ext4 helper.
    assert!(m.create_mknod(2, b"bogus", 0x8000 | 0o644, 0).is_err());
}

#[test]
fn create_persists_across_remount() {
    let disk = build_disk();
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        m.create_file(2, b"persist", 0o644).unwrap();
    }
    let m2 = ext4::Mount::open(disk).unwrap();
    assert!(m2.lookup_path(b"/persist").is_ok(), "create survived remount");
}
