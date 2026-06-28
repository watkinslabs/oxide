//! B235 coupling: ext4 regular-file `i_mapping` is the owning mount's shared
//! per-inode page cache, so two mappers/readers of one inode hit the SAME
//! cached pages (not a separate per-`InodeFileBacking` cache).

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, InodeId, MemDisk};
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
fn two_mappers_share_one_page_cache() {
    let m = ext4::rootfs::Ext4Mount::open(build_disk()).unwrap();
    let st = m.state();
    let ino = st.lookup_path(b"/hello.txt").expect("hello.txt");

    // Two independent VFS wrappers of the SAME inode — modelling two `mmap()`s,
    // each of which would otherwise own a private `InodeFileBacking` cache.
    let a = st.wrap_file(ino).expect("wrap a");
    let b = st.wrap_file(ino).expect("wrap b");
    let ma = a.i_mapping().expect("ext4 regular file exposes i_mapping");
    let mb = b.i_mapping().expect("ext4 regular file exposes i_mapping");

    // First mapper faults the page in.
    let mut ba = [0u8; 16];
    let na = ma.read_at(0, &mut ba).expect("read a");
    assert!(na > 0, "hello.txt is non-empty");
    let cached_after_a = st.page_cache.cached_count();
    assert!(st.page_cache.lookup(InodeId(ino as u64), 0).is_some(),
        "first read populated the shared cache");

    // Second mapper reads the same offset: it must REUSE the shared page
    // (no new cache entry) and see identical bytes.
    let mut bb = [0u8; 16];
    let nb = mb.read_at(0, &mut bb).expect("read b");
    let cached_after_b = st.page_cache.cached_count();

    assert_eq!(&ba[..na], &bb[..nb], "both mappers see identical bytes");
    assert_eq!(cached_after_a, cached_after_b,
        "second mapper reused the shared cache — no second per-backing page");
}
