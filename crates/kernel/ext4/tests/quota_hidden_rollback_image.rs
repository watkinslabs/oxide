extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::superblock::SB_RDONLY;
use vfs::{SuperBlock, VfsError};

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
const EXT4_RO_COMPAT_OFF: usize = EXT4_SUPERBLOCK_OFFSET + 0x64;
const EXT4_USR_QUOTA_INUM_OFF: usize = EXT4_SUPERBLOCK_OFFSET + ext4::superblock::SB_OFF_USR_QUOTA_INUM;
const EXT4_GRP_QUOTA_INUM_OFF: usize = EXT4_SUPERBLOCK_OFFSET + ext4::superblock::SB_OFF_GRP_QUOTA_INUM;
const EXT4_PRJ_QUOTA_INUM_OFF: usize = EXT4_SUPERBLOCK_OFFSET + ext4::superblock::SB_OFF_PRJ_QUOTA_INUM;
const EXT4_FEATURE_RO_COMPAT_QUOTA: u32 = 0x0100;
const EXT4_FEATURE_RO_COMPAT_PROJECT: u32 = ext4::superblock::RO_COMPAT_PROJECT;
const USR_QUOTA_INO: u32 = 3;
const GRP_QUOTA_INO: u32 = 4;
const HELLO_INO: u32 = 12;
const USR_MAGIC: u32 = 0xd9c0_1f11;
const GRP_MAGIC: u32 = 0xd9c0_1927;
const V2_VERSION_V1: u32 = 1;

fn shared_disk_from(image: Vec<u8>) -> Arc<dyn BlockDevice> {
    let cap = (image.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest { op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: image, ..Default::default() };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

fn patch_u32(disk: &Arc<dyn BlockDevice>, offset: usize, value: u32) {
    let start_block = (offset / SECTOR as usize) as u64;
    let in_block = offset % SECTOR as usize;
    let mut buffer = vec![0u8; SECTOR as usize];
    let mut req = BlockRequest { op: BlockOp::Read, start_block, len_blocks: 1, buffer, ..Default::default() };
    disk.submit_sync(&mut req).expect("read fixture sector");
    buffer = req.buffer;
    buffer[in_block..in_block + 4].copy_from_slice(&value.to_le_bytes());
    let mut req = BlockRequest { op: BlockOp::Write, start_block, len_blocks: 1, buffer, ..Default::default() };
    disk.submit_sync(&mut req).expect("write fixture sector");
}

fn patch_or_u32(disk: &Arc<dyn BlockDevice>, offset: usize, value: u32) {
    let start_block = (offset / SECTOR as usize) as u64;
    let in_block = offset % SECTOR as usize;
    let mut buffer = vec![0u8; SECTOR as usize];
    let mut req = BlockRequest { op: BlockOp::Read, start_block, len_blocks: 1, buffer, ..Default::default() };
    disk.submit_sync(&mut req).expect("read fixture sector");
    buffer = req.buffer;
    let cur = u32::from_le_bytes([buffer[in_block], buffer[in_block + 1], buffer[in_block + 2], buffer[in_block + 3]]);
    buffer[in_block..in_block + 4].copy_from_slice(&(cur | value).to_le_bytes());
    let mut req = BlockRequest { op: BlockOp::Write, start_block, len_blocks: 1, buffer, ..Default::default() };
    disk.submit_sync(&mut req).expect("write fixture sector");
}

fn empty_quota_file(magic: u32) -> Vec<u8> {
    let mut q = vec![0u8; 2048];
    q[0..4].copy_from_slice(&magic.to_le_bytes());
    q[4..8].copy_from_slice(&V2_VERSION_V1.to_le_bytes());
    q[20..24].copy_from_slice(&2u32.to_le_bytes());
    q
}

fn valid_user_group_invalid_project_disk() -> Arc<dyn BlockDevice> {
    let disk = shared_disk_from(IMAGE.to_vec());
    let m = ext4::rootfs::Ext4Mount::open(disk.clone()).expect("seed Ext4Mount::open");
    m.state().mount.init_inode(2, USR_QUOTA_INO, ext4::inode::S_IFREG | 0o600, 1, 0, 0).expect("init user quota inode");
    m.state().mount.init_inode(2, GRP_QUOTA_INO, ext4::inode::S_IFREG | 0o600, 1, 0, 0).expect("init group quota inode");
    m.state().mount.write_at(USR_QUOTA_INO, 0, &empty_quota_file(USR_MAGIC)).expect("seed user quota");
    m.state().mount.write_at(GRP_QUOTA_INO, 0, &empty_quota_file(GRP_MAGIC)).expect("seed group quota");
    drop(m);
    patch_or_u32(&disk, EXT4_RO_COMPAT_OFF, EXT4_FEATURE_RO_COMPAT_QUOTA | EXT4_FEATURE_RO_COMPAT_PROJECT);
    patch_u32(&disk, EXT4_USR_QUOTA_INUM_OFF, USR_QUOTA_INO);
    patch_u32(&disk, EXT4_GRP_QUOTA_INUM_OFF, GRP_QUOTA_INO);
    patch_u32(&disk, EXT4_PRJ_QUOTA_INUM_OFF, HELLO_INO);
    disk
}

fn open_fs(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<dyn FileSystem>, Option<vfs::InodeRef>) {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    (m, fs, root)
}

fn mount_readonly_result(disk: Arc<dyn BlockDevice>) -> vfs::KResult<(Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>)> {
    let (m, fs, root) = open_fs(disk);
    let sb = common::realize_sb_readonly_result(fs, root, 0xE471_F1A6, String::from("ext4"))?;
    Ok((m, sb))
}

#[test]
fn hidden_quota_mount_later_class_failure_surfaces_prior_quota_off_failure() {
    common::boot_hosted_pmm();
    let (m, fs, root) = open_fs(valid_user_group_invalid_project_disk());
    m.state().mount.fail_next_quota_info_write_for_tests();

    let err = match common::realize_sb_result(fs, root, 0xE471_F1A6, String::from("ext4")) {
        Ok(_) => panic!("mount realization succeeds"),
        Err(e) => e,
    };

    assert_eq!(err, VfsError::Eio);
}

#[test]
fn hidden_quota_ro_to_rw_remount_later_class_failure_surfaces_prior_quota_off_failure() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_readonly_result(valid_user_group_invalid_project_disk()).expect("RO mount");
    assert!(sb.is_readonly(), "fixture starts read-only");
    assert!(!sb.s_dquot.is_enabled(vfs::QuotaType::User));
    assert!(!sb.s_dquot.is_enabled(vfs::QuotaType::Group));
    assert!(!sb.s_dquot.is_enabled(vfs::QuotaType::Project));
    m.state().mount.fail_next_quota_info_write_for_tests();

    assert_eq!(sb.reconfigure_super(0, SB_RDONLY, ""), Err(VfsError::Eio));

    assert!(sb.is_readonly(), "failed remount leaves SB_RDONLY set");
    assert!(!sb.s_dquot.is_enabled(vfs::QuotaType::Project), "later failed class stays inactive");
}
