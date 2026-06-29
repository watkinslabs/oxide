//! B235 coupling: ext4 `Inode::getattr` reports REAL on-disk `i_blocks`
//! (`st_blocks`) and device `st_rdev`, not the size-derived generic estimate.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::Inode;
use vfs::idmap::Idmap;

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

// A preallocated (`fallocate` keep_size) file has allocated blocks beyond its
// logical size, so `st_blocks` from the REAL `i_blocks` must exceed the
// generic `blocks_for(size)` estimate — the exact sparse/prealloc case the
// generic path cannot express.
#[test]
fn st_blocks_reflects_real_allocation_not_size() {
    let m = ext4::rootfs::Ext4Mount::open(build_disk()).unwrap();
    let st = m.state();
    let inode = st.create_at(b"/prealloc.bin", 0o644).expect("create");
    // Preallocate 4 fs-blocks (16 KiB) but keep the file size at 0.
    inode.fallocate(0, 16 * 1024, /*keep_size=*/true, /*zero_range=*/false)
        .expect("fallocate keep_size");

    let k = inode.getattr(&Idmap::identity(), None);
    let bsize = inode.i_sb().map(|s| s.s_blocksize).unwrap_or_else(|| inode.blksize());
    let generic = vfs::getattr::blocks_for(k.size, bsize);

    assert!(k.blocks > generic,
        "real st_blocks ({}) must exceed the size-derived estimate ({}) for a preallocated file (size={})",
        k.blocks, generic, k.size);
    // st_blocks is in 512-byte sectors: 16 KiB of data alone is 32 sectors;
    // with extent-tree metadata it is at least that.
    assert!(k.blocks >= 32, "expected >=32 sectors for 16 KiB prealloc, got {}", k.blocks);
}

// A device node reports its `st_rdev`; non-device inodes report 0.
#[test]
fn st_rdev_reported_for_char_device() {
    let m = ext4::rootfs::Ext4Mount::open(build_disk()).unwrap();
    let st = m.state();
    let rdev: u32 = (5 << 8) | 1; // legacy (major<<8)|minor, e.g. /dev/zero-ish
    st.mknod_at(b"/cdev", ext4::inode::S_IFCHR | 0o666, rdev).expect("mknod");

    let node = st.lookup_inode_any(b"/cdev").expect("lookup cdev");
    let k = node.getattr(&Idmap::identity(), None);
    assert_eq!(k.rdev, rdev, "char-device st_rdev must round-trip the stored device number");

    // A regular file leaves st_rdev at 0.
    let reg = st.create_at(b"/plain", 0o644).expect("create plain");
    assert_eq!(reg.getattr(&Idmap::identity(), None).rdev, 0, "non-device st_rdev is 0");
}
