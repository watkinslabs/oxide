//! P7b-03 integration: dir_link + dir_unlink against mini.img.

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
fn dir_link_visible_to_lookup() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let target_ino = m.lookup_path(b"/hello.txt").unwrap();
    m.dir_link(2, b"alias", target_ino, ext4::DT_REG).unwrap();
    let got = m.lookup_path(b"/alias").unwrap();
    assert_eq!(got, target_ino, "alias resolves to same inode as hello.txt");
}

#[test]
fn dir_unlink_makes_lookup_miss() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.lookup_path(b"/hello.txt").unwrap();
    let removed = m.dir_unlink(2, b"hello.txt").unwrap();
    assert_eq!(removed, n);
    assert_eq!(m.lookup_path(b"/hello.txt").err().unwrap(), ext4::MountError::NotFound);
}

#[test]
fn dir_link_persists_across_remount() {
    let disk = build_disk();
    let target = {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let t = m.lookup_path(b"/hello.txt").unwrap();
        m.dir_link(2, b"alias2", t, ext4::DT_REG).unwrap();
        t
    };
    let m2 = ext4::Mount::open(disk).unwrap();
    assert_eq!(m2.lookup_path(b"/alias2").unwrap(), target);
}

#[test]
fn dir_unlink_missing_is_notfound() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    assert_eq!(m.dir_unlink(2, b"no-such-name").err().unwrap(),
               ext4::MountError::NotFound);
}
