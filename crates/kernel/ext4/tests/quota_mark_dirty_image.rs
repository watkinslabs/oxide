extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{Kqid, MemDqblk, SuperBlock};

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
const EXT4_RO_COMPAT_OFF: usize = EXT4_SUPERBLOCK_OFFSET + 0x64;
const EXT4_PRJ_QUOTA_INUM_OFF: usize =
    EXT4_SUPERBLOCK_OFFSET + ext4::superblock::SB_OFF_PRJ_QUOTA_INUM;
const EXT4_FEATURE_RO_COMPAT_QUOTA: u32 = ext4::superblock::RO_COMPAT_QUOTA;
const EXT4_FEATURE_RO_COMPAT_PROJECT: u32 = ext4::superblock::RO_COMPAT_PROJECT;
const QUOTA_INO: u32 = 12;
const PRJ_MAGIC: u32 = 0xd9c0_3f14;
const V2_VERSION_V1: u32 = 1;

fn shared_disk_from(image: Vec<u8>) -> Arc<dyn BlockDevice> {
    let cap = image.len() as u64 / SECTOR as u64;
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write,
        start_block: 0,
        len_blocks: cap as u32,
        buffer: image,
        ..Default::default()
    };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

fn patch_u32(disk: &Arc<dyn BlockDevice>, offset: usize, value: u32) {
    let start_block = (offset / SECTOR as usize) as u64;
    let in_block = offset % SECTOR as usize;
    let mut req = BlockRequest {
        op: BlockOp::Read,
        start_block,
        len_blocks: 1,
        buffer: vec![0u8; SECTOR as usize],
        ..Default::default()
    };
    disk.submit_sync(&mut req).expect("read fixture sector");
    req.buffer[in_block..in_block + 4].copy_from_slice(&value.to_le_bytes());
    req.op = BlockOp::Write;
    disk.submit_sync(&mut req).expect("write fixture sector");
}

fn empty_project_quota_file() -> Vec<u8> {
    let mut q = vec![0u8; 2048];
    q[0..4].copy_from_slice(&PRJ_MAGIC.to_le_bytes());
    q[4..8].copy_from_slice(&V2_VERSION_V1.to_le_bytes());
    q[20..24].copy_from_slice(&2u32.to_le_bytes());
    q
}

fn quota_disk() -> Arc<dyn BlockDevice> {
    let disk = shared_disk_from(IMAGE.to_vec());
    let mount = ext4::rootfs::Ext4Mount::open(disk.clone()).expect("seed ext4 mount");
    mount
        .state()
        .mount
        .write_at(QUOTA_INO, 0, &empty_project_quota_file())
        .expect("seed quota file");
    drop(mount);
    patch_u32(
        &disk,
        EXT4_RO_COMPAT_OFF,
        EXT4_FEATURE_RO_COMPAT_QUOTA | EXT4_FEATURE_RO_COMPAT_PROJECT,
    );
    patch_u32(&disk, EXT4_PRJ_QUOTA_INUM_OFF, QUOTA_INO);
    disk
}

fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let mount = ext4::rootfs::Ext4Mount::open(disk).expect("open ext4 mount");
    let fs: Arc<dyn FileSystem> = mount.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_D117, String::from("ext4"));
    (mount, sb)
}

#[test]
fn quota_feature_mark_dirty_commits_without_q_sync() {
    common::boot_hosted_pmm();
    let disk = quota_disk();
    let (_writer_mount, writer_sb) = mount(disk.clone());
    let qid = Kqid::project(2514);
    let want = MemDqblk {
        dqb_bhardlimit: 64 * 1024,
        dqb_curspace: 4096,
        dqb_ihardlimit: 8,
        dqb_curinodes: 1,
        ..MemDqblk::new()
    };

    vfs::quota_setquota(&writer_sb, qid, want).expect("set quota through the live VFS path");

    // Keep the writer mounted: dropping it or issuing Q_SYNC would mask a
    // deferred mark-dirty implementation by flushing the cached dquot.
    let (_reader_mount, reader_sb) = mount(disk);
    assert_eq!(
        vfs::quota_getquota(&reader_sb, qid).expect("read synchronously committed quota"),
        want,
    );
}
