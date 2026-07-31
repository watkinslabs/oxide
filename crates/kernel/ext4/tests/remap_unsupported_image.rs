//! Linux ext4 does not install `file_operations::remap_file_range`, so
//! FICLONE/FIDEDUPERANGE reach VFS admission and fail with EOPNOTSUPP rather
//! than doing a copy fallback.

extern crate alloc;
mod common;
use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{Dentry, File, OpenFlags, SuperBlock, VfsError};

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;

fn shared_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    common::boot_hosted_pmm();
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_F1A7, String::from("ext4"));
    (m, sb)
}

#[test]
fn ext4_regular_file_remap_is_unsupported_like_linux() {
    let disk = shared_disk();
    let (m, _sb) = mount(disk);
    let inode = m.state().create_at(b"/src.bin", 0o644).expect("create");
    let dentry = Dentry::new_root(inode.clone());
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);

    assert!(!file.supports_remap_file_range());
    assert_eq!(file.remap_file_range(0, &file, 0, 4096, 0), Err(VfsError::Eopnotsupp));
}
