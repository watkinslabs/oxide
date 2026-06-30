//! B235 / D8 coupling: ext4 regular-file `i_mapping` is the inode's per-inode
//! PMM frame store, so the SAME inode (Linux `iget` shared identity) hands
//! every mapper/reader ONE coherent page cache — two handles read identical
//! bytes from the SAME backing frame.
//!
//! (Before D8 the read path served from the per-mount `Vec` page cache; reads
//! now serve from the per-inode frame store, so this asserts on the frame
//! identity, not the legacy `Vec` cache.)

extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::SuperBlock;

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
fn two_mappers_share_one_inode_page_cache() {
    common::boot_hosted_pmm();
    let m = ext4::rootfs::Ext4Mount::open(build_disk()).unwrap();
    // Back-stamp a SuperBlock so `wrap_file` shares one inode (iget).
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let _sb = SuperBlock::for_backend(fs.clone(), root, 0x1234_5678, String::from("ext4"));

    let ino = m.state().lookup_path(b"/hello.txt").expect("hello.txt");

    // Two wrappers of the SAME inode — the shared `iget` identity gives ONE
    // `i_mapping` / one frame store, the coherency guarantee a real mmap relies
    // on (path lookup → iget → same inode).
    let a = m.state().wrap_file(ino).expect("wrap a");
    let b = m.state().wrap_file(ino).expect("wrap b");
    assert!(Arc::ptr_eq(&a, &b), "iget returns the SAME inode Arc");

    let ma = a.i_mapping().expect("ext4 regular file exposes i_mapping");
    let mb = b.i_mapping().expect("ext4 regular file exposes i_mapping");

    // Both read the same bytes from the same backing.
    let mut ba = [0u8; 16];
    let na = ma.read_at(0, &mut ba).expect("read a");
    assert!(na > 0, "hello.txt is non-empty");

    let mut bb = [0u8; 16];
    let nb = mb.read_at(0, &mut bb).expect("read b");
    assert_eq!(&ba[..na], &bb[..nb], "both mappers see identical bytes");

    // And both hand out the SAME MAP_SHARED frame for page 0 (one cache).
    assert_eq!(ma.shared_frame(0), mb.shared_frame(0),
        "both mappers alias the SAME inode frame — one page cache");
}
