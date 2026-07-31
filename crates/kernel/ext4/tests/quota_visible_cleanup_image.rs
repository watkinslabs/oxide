extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::SuperBlock;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
const EXT4_RO_COMPAT_OFF: usize = EXT4_SUPERBLOCK_OFFSET + 0x64;
const EXT4_FEATURE_RO_COMPAT_PROJECT: u32 = ext4::superblock::RO_COMPAT_PROJECT;
const PRJ_MAGIC: u32 = 0xd9c0_3f14;
const V2_VERSION_V1: u32 = 1;
const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
const FS_NOATIME_FL: u32 = 0x0000_0080;

fn shared_disk_from(image: Vec<u8>) -> Arc<dyn BlockDevice> {
    let cap = (image.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: image, ..Default::default() };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

fn quota_disk() -> Arc<dyn BlockDevice> {
    let mut image = IMAGE.to_vec();
    let mut features = u32::from_le_bytes(image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4].try_into().unwrap());
    features |= EXT4_FEATURE_RO_COMPAT_PROJECT;
    image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4].copy_from_slice(&features.to_le_bytes());
    shared_disk_from(image)
}

fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb_result(fs, root, 0xE471_F1A6, String::from("ext4")).expect("realize ext4 sb");
    (m, sb)
}

fn empty_project_quota_file() -> Vec<u8> {
    let mut q = alloc::vec![0u8; 2048];
    q[0..4].copy_from_slice(&PRJ_MAGIC.to_le_bytes());
    q[4..8].copy_from_slice(&V2_VERSION_V1.to_le_bytes());
    q[20..24].copy_from_slice(&2u32.to_le_bytes());
    q
}

#[test]
fn visible_quota_off_clear_failure_retains_retry_state() {
    common::boot_hosted_pmm();
    let disk = quota_disk();
    let (m, sb) = mount(disk);
    let qfile = m.state().create_at(b"/visible-cleanup.quota", 0o600).expect("create visible quota");
    let qino = qfile.ino() as u32;
    m.state().mount.write_at(qino, 0, &empty_project_quota_file()).expect("seed visible quota");
    let root = sb.s_root().expect("root dentry");
    let qpath = vfs::path_lookup_path(root.clone(), root, "/visible-cleanup.quota", vfs::LookupFlags::default()).expect("resolve visible quota");

    sb.s_op.quota_on(&sb, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, Some(&qpath)).expect("quota_on visible");
    assert_ne!(qfile.i_flags() & (vfs::S_IMMUTABLE | vfs::S_NOATIME), 0);
    let raw_after_on = m.state().mount.read_inode(qino).expect("raw quota after on");
    assert_ne!(raw_after_on.i_flags & (FS_IMMUTABLE_FL | FS_NOATIME_FL), 0);

    m.state().mount.fail_next_inode_write_for_tests();
    assert_eq!(vfs::quota_off(&sb, vfs::QuotaType::Project), Err(vfs::VfsError::Eio));
    assert!(sb.s_dquot.is_closing(vfs::QuotaType::Project), "failed quota-off remains retryable");
    assert_ne!(qfile.i_flags() & (vfs::S_IMMUTABLE | vfs::S_NOATIME), 0, "in-memory visible flags stay protected after failed clear");
    let raw_after_fail = m.state().mount.read_inode(qino).expect("raw quota after failed off");
    assert_ne!(raw_after_fail.i_flags & (FS_IMMUTABLE_FL | FS_NOATIME_FL), 0, "raw visible flags stay protected after failed clear");

    vfs::quota_off(&sb, vfs::QuotaType::Project).expect("retry quota_off visible");
    assert!(!sb.s_dquot.is_closing(vfs::QuotaType::Project));
    assert_eq!(qfile.i_flags() & (vfs::S_IMMUTABLE | vfs::S_NOATIME), 0);
    let raw_after_retry = m.state().mount.read_inode(qino).expect("raw quota after retry");
    assert_eq!(raw_after_retry.i_flags & (FS_IMMUTABLE_FL | FS_NOATIME_FL), 0);
}

#[test]
fn visible_quota_off_preserves_preexisting_immutable_noatime_flags() {
    common::boot_hosted_pmm();
    let disk = quota_disk();
    let (m, sb) = mount(disk);
    let qfile = m.state().create_at(b"/visible-preexisting.quota", 0o600).expect("create visible quota");
    let qino = qfile.ino() as u32;
    m.state().mount.write_at(qino, 0, &empty_project_quota_file()).expect("seed visible quota");
    let raw = m.state().mount.read_inode(qino).expect("raw quota before flags");
    m.state().mount.persist_inode_flags_only(qino, raw.i_flags | FS_IMMUTABLE_FL | FS_NOATIME_FL)
        .expect("set preexisting flags");
    qfile.set_i_flags(qfile.i_flags() | vfs::S_IMMUTABLE | vfs::S_NOATIME);
    let root = sb.s_root().expect("root dentry");
    let qpath = vfs::path_lookup_path(root.clone(), root, "/visible-preexisting.quota", vfs::LookupFlags::default()).expect("resolve visible quota");

    sb.s_op.quota_on(&sb, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, Some(&qpath)).expect("quota_on visible");
    vfs::quota_off(&sb, vfs::QuotaType::Project).expect("quota_off visible");

    assert_eq!(qfile.i_flags() & (vfs::S_IMMUTABLE | vfs::S_NOATIME), vfs::S_IMMUTABLE | vfs::S_NOATIME);
    let raw_after = m.state().mount.read_inode(qino).expect("raw quota after off");
    assert_eq!(raw_after.i_flags & (FS_IMMUTABLE_FL | FS_NOATIME_FL), FS_IMMUTABLE_FL | FS_NOATIME_FL);
}

#[test]
fn visible_quota_on_mark_failure_preserves_preexisting_flags() {
    common::boot_hosted_pmm();
    let disk = quota_disk();
    let (m, sb) = mount(disk);
    let qfile = m.state().create_at(b"/visible-mark-fail.quota", 0o600).expect("create visible quota");
    let qino = qfile.ino() as u32;
    m.state().mount.write_at(qino, 0, &empty_project_quota_file()).expect("seed visible quota");
    let raw = m.state().mount.read_inode(qino).expect("raw quota before flags");
    m.state().mount.persist_inode_flags_only(qino, raw.i_flags | FS_IMMUTABLE_FL | FS_NOATIME_FL)
        .expect("set preexisting flags");
    qfile.set_i_flags(qfile.i_flags() | vfs::S_IMMUTABLE | vfs::S_NOATIME);
    let root = sb.s_root().expect("root dentry");
    let qpath = vfs::path_lookup_path(root.clone(), root, "/visible-mark-fail.quota", vfs::LookupFlags::default()).expect("resolve visible quota");

    m.state().mount.fail_next_inode_write_for_tests();
    assert_eq!(sb.s_op.quota_on(&sb, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, Some(&qpath)), Err(vfs::VfsError::Eio));

    assert!(!sb.s_dquot.is_enabled(vfs::QuotaType::Project));
    assert_eq!(qfile.i_flags() & (vfs::S_IMMUTABLE | vfs::S_NOATIME), vfs::S_IMMUTABLE | vfs::S_NOATIME);
    let raw_after = m.state().mount.read_inode(qino).expect("raw quota after failed on");
    assert_eq!(raw_after.i_flags & (FS_IMMUTABLE_FL | FS_NOATIME_FL), FS_IMMUTABLE_FL | FS_NOATIME_FL);
}

#[test]
fn failed_visible_quotaon_does_not_replace_retry_cleanup_file() {
    common::boot_hosted_pmm();
    let disk = quota_disk();
    let (m, sb) = mount(disk);
    let a = m.state().create_at(b"/visible-a.quota", 0o600).expect("create visible quota A");
    let b = m.state().create_at(b"/visible-b.quota", 0o600).expect("create visible quota B");
    let aino = a.ino() as u32;
    let bino = b.ino() as u32;
    m.state().mount.write_at(aino, 0, &empty_project_quota_file()).expect("seed visible quota A");
    m.state().mount.write_at(bino, 0, &empty_project_quota_file()).expect("seed visible quota B");
    let root = sb.s_root().expect("root dentry");
    let apath = vfs::path_lookup_path(root.clone(), root.clone(), "/visible-a.quota", vfs::LookupFlags::default()).expect("resolve A");
    let bpath = vfs::path_lookup_path(root.clone(), root, "/visible-b.quota", vfs::LookupFlags::default()).expect("resolve B");

    sb.s_op.quota_on(&sb, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, Some(&apath)).expect("quota_on A");
    m.state().mount.fail_next_inode_write_for_tests();
    assert_eq!(vfs::quota_off(&sb, vfs::QuotaType::Project), Err(vfs::VfsError::Eio));
    assert!(sb.s_dquot.is_closing(vfs::QuotaType::Project));

    assert_eq!(sb.s_op.quota_on(&sb, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, Some(&bpath)), Err(vfs::VfsError::Ebusy));
    vfs::quota_off(&sb, vfs::QuotaType::Project).expect("retry quota_off A");

    let araw = m.state().mount.read_inode(aino).expect("raw A after retry");
    let braw = m.state().mount.read_inode(bino).expect("raw B after retry");
    assert_eq!(araw.i_flags & (FS_IMMUTABLE_FL | FS_NOATIME_FL), 0, "retry clears original visible quota file");
    assert_eq!(braw.i_flags & (FS_IMMUTABLE_FL | FS_NOATIME_FL), 0, "failed quota_on does not make B the cleanup file");
}
