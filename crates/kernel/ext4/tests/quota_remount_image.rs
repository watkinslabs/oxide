extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::superblock::SB_RDONLY;
use vfs::SuperBlock;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
const EXT4_RO_COMPAT_OFF: usize = EXT4_SUPERBLOCK_OFFSET + 0x64;
const EXT4_USR_QUOTA_INUM_OFF: usize = EXT4_SUPERBLOCK_OFFSET + ext4::superblock::SB_OFF_USR_QUOTA_INUM;
const EXT4_PRJ_QUOTA_INUM_OFF: usize = EXT4_SUPERBLOCK_OFFSET + ext4::superblock::SB_OFF_PRJ_QUOTA_INUM;
const EXT4_FEATURE_RO_COMPAT_QUOTA: u32 = 0x0100;
const EXT4_FEATURE_RO_COMPAT_PROJECT: u32 = ext4::superblock::RO_COMPAT_PROJECT;
const USR_QUOTA_INO: u32 = 3;
const HELLO_INO: u32 = 12;
const USR_MAGIC: u32 = 0xd9c0_1f11;
const PRJ_MAGIC: u32 = 0xd9c0_3f14;
const V2_VERSION_V1: u32 = 1;

fn shared_disk_from(image: Vec<u8>) -> Arc<dyn BlockDevice> {
    let cap = (image.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: image, ..Default::default() };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

fn patch_u32(disk: &Arc<dyn BlockDevice>, offset: usize, value: u32) {
    let start_block = (offset / SECTOR as usize) as u64;
    let in_block = offset % SECTOR as usize;
    let mut buffer = alloc::vec![0u8; SECTOR as usize];
    let mut req = BlockRequest { op: BlockOp::Read, start_block, len_blocks: 1, buffer, ..Default::default() };
    disk.submit_sync(&mut req).expect("read fixture sector");
    buffer = req.buffer;
    buffer[in_block..in_block + 4].copy_from_slice(&value.to_le_bytes());
    let mut req = BlockRequest { op: BlockOp::Write, start_block, len_blocks: 1, buffer, ..Default::default() };
    disk.submit_sync(&mut req).expect("write fixture sector");
}

fn seeded_quota_disk() -> Arc<dyn BlockDevice> {
    let disk = shared_disk_from(IMAGE.to_vec());
    let m = ext4::rootfs::Ext4Mount::open(disk.clone()).expect("seed Ext4Mount::open");
    m.state().mount.write_at(HELLO_INO, 0, &empty_project_quota_file()).expect("seed quota file");
    drop(m);
    patch_u32(&disk, EXT4_RO_COMPAT_OFF, EXT4_FEATURE_RO_COMPAT_QUOTA | EXT4_FEATURE_RO_COMPAT_PROJECT);
    patch_u32(&disk, EXT4_PRJ_QUOTA_INUM_OFF, HELLO_INO);
    disk
}

fn seeded_user_project_quota_disk() -> Arc<dyn BlockDevice> {
    let disk = shared_disk_from(IMAGE.to_vec());
    let m = ext4::rootfs::Ext4Mount::open(disk.clone()).expect("seed Ext4Mount::open");
    m.state().mount.init_inode(2, USR_QUOTA_INO, ext4::inode::S_IFREG | 0o600, 1, 0, 0).expect("init user quota inode");
    m.state().mount.write_at(USR_QUOTA_INO, 0, &empty_quota_file(USR_MAGIC)).expect("seed user quota");
    m.state().mount.write_at(HELLO_INO, 0, &empty_project_quota_file()).expect("seed project quota");
    drop(m);
    patch_u32(&disk, EXT4_RO_COMPAT_OFF, EXT4_FEATURE_RO_COMPAT_QUOTA | EXT4_FEATURE_RO_COMPAT_PROJECT);
    patch_u32(&disk, EXT4_USR_QUOTA_INUM_OFF, USR_QUOTA_INO);
    patch_u32(&disk, EXT4_PRJ_QUOTA_INUM_OFF, HELLO_INO);
    disk
}

fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb_result(fs, root, 0xE471_F1A6, String::from("ext4")).expect("realize ext4 sb");
    (m, sb)
}

fn empty_project_quota_file() -> Vec<u8> {
    empty_quota_file(PRJ_MAGIC)
}

fn empty_quota_file(magic: u32) -> Vec<u8> {
    let mut q = alloc::vec![0u8; 2048];
    q[0..4].copy_from_slice(&magic.to_le_bytes());
    q[4..8].copy_from_slice(&V2_VERSION_V1.to_le_bytes());
    q[20..24].copy_from_slice(&2u32.to_le_bytes());
    q
}

#[test]
fn rw_to_ro_remount_suspends_hidden_quota_accounting() {
    common::boot_hosted_pmm();
    let (_m, sb) = mount(seeded_quota_disk());
    let kind = vfs::QuotaType::Project;
    assert!(sb.s_dquot.is_enabled(kind));
    assert!(!sb.s_dquot.is_enforced(kind));

    sb.reconfigure_super(SB_RDONLY, 0).expect("RW→RO remount");

    assert!(sb.is_readonly());
    assert!(!sb.s_dquot.is_enabled(kind), "RW→RO suspends hidden quota accounting");
    assert_eq!(vfs::quota_getfmt(&sb, kind), Err(vfs::VfsError::Esrch));
}

#[test]
fn ext4_sysfile_quota_hooks_toggle_enforcement_only() {
    common::boot_hosted_pmm();
    let (_m, sb) = mount(seeded_quota_disk());
    let kind = vfs::QuotaType::Project;
    assert!(sb.s_dquot.is_enabled(kind));
    assert!(!sb.s_dquot.is_enforced(kind));

    sb.s_op.quota_enable(&sb, kind).expect("sysfile quota_enable");
    assert!(sb.s_dquot.is_enabled(kind));
    assert!(sb.s_dquot.is_enforced(kind));
    assert_eq!(sb.s_op.quota_enable(&sb, kind), Err(vfs::VfsError::Eexist));

    sb.s_op.quota_disable(&sb, kind).expect("sysfile quota_disable");
    assert!(sb.s_dquot.is_enabled(kind));
    assert!(!sb.s_dquot.is_enforced(kind));
    assert_eq!(sb.s_op.quota_disable(&sb, kind), Err(vfs::VfsError::Eexist));
}

#[test]
fn ro_to_rw_remount_restores_prior_hidden_quota_enforcement() {
    common::boot_hosted_pmm();
    let (_m, sb) = mount(seeded_quota_disk());
    let kind = vfs::QuotaType::Project;
    vfs::quota_enable_limits(&sb, kind).expect("enable project limits");
    assert!(sb.s_dquot.is_enforced(kind));

    sb.reconfigure_super(SB_RDONLY, 0).expect("RW→RO remount");
    assert!(sb.is_readonly());
    assert!(!sb.s_dquot.is_enabled(kind));

    sb.reconfigure_super(0, SB_RDONLY).expect("RO→RW remount");

    assert!(!sb.is_readonly());
    assert!(sb.s_dquot.is_enabled(kind), "RO→RW resumes hidden quota accounting");
    assert!(sb.s_dquot.is_enforced(kind), "RO→RW restores prior enforcement state");
    assert_eq!(vfs::quota_getinfo(&sb, kind).expect("quota info").dqi_flags & vfs::DQF_SYS_FILE, vfs::DQF_SYS_FILE);
}

#[test]
fn ro_to_rw_remount_keeps_default_hidden_quota_limits_disabled() {
    common::boot_hosted_pmm();
    let (_m, sb) = mount(seeded_quota_disk());
    let kind = vfs::QuotaType::Project;
    assert!(!sb.s_dquot.is_enforced(kind));

    sb.reconfigure_super(SB_RDONLY, 0).expect("RW→RO remount");
    sb.reconfigure_super(0, SB_RDONLY).expect("RO→RW remount");

    assert!(!sb.is_readonly());
    assert!(sb.s_dquot.is_enabled(kind));
    assert!(!sb.s_dquot.is_enforced(kind), "default hidden quota remains accounting-only");
}

#[test]
fn failed_ro_to_rw_remount_preserves_suspended_enforcement_for_retry() {
    common::boot_hosted_pmm();
    let (m, sb) = mount(seeded_user_project_quota_disk());
    let user = vfs::QuotaType::User;
    let project = vfs::QuotaType::Project;
    vfs::quota_enable_limits(&sb, user).expect("enable user limits");
    assert!(sb.s_dquot.is_enforced(user));

    sb.reconfigure_super(SB_RDONLY, 0).expect("RW→RO remount");
    assert!(sb.is_readonly());
    assert!(!sb.s_dquot.is_enabled(user));
    assert!(!sb.s_dquot.is_enabled(project));
    m.state().mount.write_at(HELLO_INO, 0, &alloc::vec![0u8; 2048]).expect("corrupt project quota file");

    assert_eq!(sb.reconfigure_super(0, SB_RDONLY), Err(vfs::VfsError::Einval));

    assert!(sb.is_readonly(), "failed RO→RW remount leaves SB_RDONLY set");
    assert!(!sb.s_dquot.is_enabled(user), "resumed user quota rolls back to suspended");
    assert!(!sb.s_dquot.is_enabled(project), "failed project quota stays inactive");
    m.state().mount.write_at(HELLO_INO, 0, &empty_project_quota_file()).expect("restore project quota file");

    sb.reconfigure_super(0, SB_RDONLY).expect("retry RO→RW remount");

    assert!(!sb.is_readonly());
    assert!(sb.s_dquot.is_enabled(user));
    assert!(sb.s_dquot.is_enforced(user), "retry restores pre-suspend user enforcement");
    assert!(sb.s_dquot.is_enabled(project));
    assert!(!sb.s_dquot.is_enforced(project), "project enforcement stays at its pre-suspend state");
}
