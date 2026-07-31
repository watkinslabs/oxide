extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{Kqid, SuperBlock, VfsError};

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
const EXT4_RO_COMPAT_OFF: usize = EXT4_SUPERBLOCK_OFFSET + 0x64;
const EXT4_USR_QUOTA_INUM_OFF: usize = EXT4_SUPERBLOCK_OFFSET + ext4::superblock::SB_OFF_USR_QUOTA_INUM;
const EXT4_GRP_QUOTA_INUM_OFF: usize = EXT4_SUPERBLOCK_OFFSET + ext4::superblock::SB_OFF_GRP_QUOTA_INUM;
const EXT4_FEATURE_RO_COMPAT_QUOTA: u32 = 0x0100;
const USR_QUOTA_INO: u32 = 3;
const GRP_QUOTA_INO: u32 = 4;
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

fn seeded_user_group_quota_disk() -> Arc<dyn BlockDevice> {
    let disk = shared_disk_from(IMAGE.to_vec());
    let m = ext4::rootfs::Ext4Mount::open(disk.clone()).expect("seed Ext4Mount::open");
    m.state().mount.init_inode(2, USR_QUOTA_INO, ext4::inode::S_IFREG | 0o600, 1, 0, 0).expect("init user quota inode");
    m.state().mount.init_inode(2, GRP_QUOTA_INO, ext4::inode::S_IFREG | 0o600, 1, 0, 0).expect("init group quota inode");
    m.state().mount.write_at(USR_QUOTA_INO, 0, &empty_quota_file(USR_MAGIC)).expect("seed user quota");
    m.state().mount.write_at(GRP_QUOTA_INO, 0, &empty_quota_file(GRP_MAGIC)).expect("seed group quota");
    drop(m);
    patch_or_u32(&disk, EXT4_RO_COMPAT_OFF, EXT4_FEATURE_RO_COMPAT_QUOTA);
    patch_u32(&disk, EXT4_USR_QUOTA_INUM_OFF, USR_QUOTA_INO);
    patch_u32(&disk, EXT4_GRP_QUOTA_INUM_OFF, GRP_QUOTA_INO);
    disk
}

fn mount_result(disk: Arc<dyn BlockDevice>) -> vfs::KResult<(Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>)> {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb_result(fs, root, 0xE471_F1A6, String::from("ext4"))?;
    Ok((m, sb))
}

#[test]
fn hidden_user_and_group_quotas_auto_activate_and_account_new_usage() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_user_group_quota_disk()).expect("rw mount with hidden user/group quota");
    assert!(sb.s_dquot.is_enabled(vfs::QuotaType::User));
    assert!(sb.s_dquot.is_enabled(vfs::QuotaType::Group));
    assert!(!sb.s_dquot.is_enabled(vfs::QuotaType::Project));
    assert_eq!(vfs::quota_getfmt(&sb, vfs::QuotaType::User).expect("user fmt"), vfs::QFMT_VFS_V1);
    assert_eq!(vfs::quota_getfmt(&sb, vfs::QuotaType::Group).expect("group fmt"), vfs::QFMT_VFS_V1);
    assert_eq!(vfs::quota_getinfo(&sb, vfs::QuotaType::User).expect("user info").dqi_flags & vfs::DQF_SYS_FILE, vfs::DQF_SYS_FILE);
    assert_eq!(vfs::quota_getinfo(&sb, vfs::QuotaType::Group).expect("group info").dqi_flags & vfs::DQF_SYS_FILE, vfs::DQF_SYS_FILE);
    assert!(!sb.s_dquot.is_enforced(vfs::QuotaType::User));
    assert!(!sb.s_dquot.is_enforced(vfs::QuotaType::Group));

    let inode = m.state().create_at(b"/user-group-quota.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0x41; bs as usize]).expect("write one block");
    let raw = m.state().mount.read_inode(ino).expect("raw after write");
    let charged = raw.i_blocks as u64 * 512;
    let uq = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota after write");
    let gq = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota after write");
    assert_eq!(uq.dqb_curinodes, 1);
    assert_eq!(gq.dqb_curinodes, 1);
    assert_eq!(uq.dqb_curspace, charged);
    assert_eq!(gq.dqb_curspace, charged);
}

#[test]
fn unlink_releases_user_and_group_inode_and_block_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_user_group_quota_disk()).expect("rw mount with hidden user/group quota");

    let inode = m.state().create_at(b"/user-group-unlink.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0x52; (bs * 2) as usize]).expect("write blocks");

    let charged = m.state().mount.read_inode(ino).expect("raw before unlink").i_blocks as u64 * 512;
    assert_ne!(charged, 0);
    let uq = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota before unlink");
    let gq = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota before unlink");
    assert_eq!(uq.dqb_curinodes, 1);
    assert_eq!(gq.dqb_curinodes, 1);
    assert_eq!(uq.dqb_curspace, charged);
    assert_eq!(gq.dqb_curspace, charged);

    drop(inode);
    m.state().unlink_at(b"/user-group-unlink.txt").expect("unlink file");

    let uq = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota after unlink");
    let gq = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota after unlink");
    assert_eq!(uq.dqb_curinodes, 0);
    assert_eq!(gq.dqb_curinodes, 0);
    assert_eq!(uq.dqb_curspace, 0);
    assert_eq!(gq.dqb_curspace, 0);
}

#[test]
fn free_orphan_inode_named_file_noops_without_releasing_user_group_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_user_group_quota_disk()).expect("rw mount with hidden user/group quota");

    let inode = m.state().create_at(b"/named-orphan-noop.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0x6E; bs as usize]).expect("write one block");

    let before_raw = m.state().mount.read_inode(ino).expect("raw before free_orphan");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_uq = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota before free_orphan");
    let before_gq = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota before free_orphan");
    assert_ne!(before_raw.i_blocks, 0);
    assert_eq!(before_uq.dqb_curspace, before_raw.i_blocks as u64 * 512);
    assert_eq!(before_gq.dqb_curspace, before_raw.i_blocks as u64 * 512);

    m.state().free_orphan_inode(ino).expect("named inode orphan free is a no-op");

    assert!(m.state().lookup_inode(b"/named-orphan-noop.txt").is_some());
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after free_orphan");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    let after_uq = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota after free_orphan");
    let after_gq = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota after free_orphan");
    assert_eq!(after_uq.dqb_curinodes, before_uq.dqb_curinodes);
    assert_eq!(after_gq.dqb_curinodes, before_gq.dqb_curinodes);
    assert_eq!(after_uq.dqb_curspace, before_uq.dqb_curspace);
    assert_eq!(after_gq.dqb_curspace, before_gq.dqb_curspace);
}

#[test]
fn hardlink_does_not_charge_and_nonfinal_unlink_does_not_release_user_group_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_user_group_quota_disk()).expect("rw mount with hidden user/group quota");

    let inode = m.state().create_at(b"/hardlink-source.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0x6d; bs as usize]).expect("write block");
    drop(inode);

    let charged = m.state().mount.read_inode(ino).expect("raw before link").i_blocks as u64 * 512;
    assert_ne!(charged, 0);
    let uq = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota before link");
    let gq = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota before link");
    assert_eq!(uq.dqb_curinodes, 1);
    assert_eq!(gq.dqb_curinodes, 1);
    assert_eq!(uq.dqb_curspace, charged);
    assert_eq!(gq.dqb_curspace, charged);

    m.state().link_at(b"/hardlink-source.txt", b"/hardlink-alias.txt").expect("hardlink file");
    assert_eq!(m.state().mount.read_inode(ino).expect("raw after link").links_count, 2);

    let uq_after_link = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota after link");
    let gq_after_link = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota after link");
    assert_eq!(uq_after_link.dqb_curinodes, uq.dqb_curinodes);
    assert_eq!(gq_after_link.dqb_curinodes, gq.dqb_curinodes);
    assert_eq!(uq_after_link.dqb_curspace, uq.dqb_curspace);
    assert_eq!(gq_after_link.dqb_curspace, gq.dqb_curspace);

    m.state().unlink_at(b"/hardlink-source.txt").expect("unlink non-final name");
    assert_eq!(m.state().mount.read_inode(ino).expect("raw after non-final unlink").links_count, 1);

    let uq_after_nonfinal = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota after non-final unlink");
    let gq_after_nonfinal = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota after non-final unlink");
    assert_eq!(uq_after_nonfinal.dqb_curinodes, 1);
    assert_eq!(gq_after_nonfinal.dqb_curinodes, 1);
    assert_eq!(uq_after_nonfinal.dqb_curspace, charged);
    assert_eq!(gq_after_nonfinal.dqb_curspace, charged);

    m.state().unlink_at(b"/hardlink-alias.txt").expect("unlink final name");

    let uq_after_final = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota after final unlink");
    let gq_after_final = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota after final unlink");
    assert_eq!(uq_after_final.dqb_curinodes, 0);
    assert_eq!(gq_after_final.dqb_curinodes, 0);
    assert_eq!(uq_after_final.dqb_curspace, 0);
    assert_eq!(gq_after_final.dqb_curspace, 0);
}

#[test]
fn linking_anonymous_inode_does_not_double_charge_user_group_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_user_group_quota_disk()).expect("rw mount with hidden user/group quota");

    let inode = m.state().create_anonymous_at(b"/", 0o600).expect("anonymous inode");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0x71; bs as usize]).expect("write anonymous block");

    let charged = m.state().mount.read_inode(ino).expect("raw anonymous").i_blocks as u64 * 512;
    assert_ne!(charged, 0);
    let uq = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota before link");
    let gq = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota before link");
    assert_eq!(uq.dqb_curinodes, 1);
    assert_eq!(gq.dqb_curinodes, 1);
    assert_eq!(uq.dqb_curspace, charged);
    assert_eq!(gq.dqb_curspace, charged);

    m.state().link_inode_at(ino, b"/linked-anonymous.txt").expect("link anonymous inode");
    assert_eq!(m.state().mount.read_inode(ino).expect("raw after link_inode_at").links_count, 1);

    let uq_after_link = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota after link");
    let gq_after_link = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota after link");
    assert_eq!(uq_after_link.dqb_curinodes, 1);
    assert_eq!(gq_after_link.dqb_curinodes, 1);
    assert_eq!(uq_after_link.dqb_curspace, charged);
    assert_eq!(gq_after_link.dqb_curspace, charged);

    drop(inode);
    m.state().unlink_at(b"/linked-anonymous.txt").expect("unlink linked anonymous inode");

    let uq_after_unlink = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota after unlink");
    let gq_after_unlink = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota after unlink");
    assert_eq!(uq_after_unlink.dqb_curinodes, 0);
    assert_eq!(gq_after_unlink.dqb_curinodes, 0);
    assert_eq!(uq_after_unlink.dqb_curspace, 0);
    assert_eq!(gq_after_unlink.dqb_curspace, 0);
}

#[test]
fn rename_overwrite_releases_replaced_user_group_quota_usage() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_user_group_quota_disk()).expect("rw mount with hidden user/group quota");

    let src = m.state().create_at(b"/ug-rename-src.txt", 0o644).expect("create source");
    let src_ino = src.ino() as u32;
    let dst = m.state().create_at(b"/ug-rename-dst.txt", 0o644).expect("create dest");
    let dst_ino = dst.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(src_ino, 0, &vec![0x81; bs as usize]).expect("write source");
    m.state().mount.write_at(dst_ino, 0, &vec![0x82; bs as usize]).expect("write dest");
    drop(src);
    drop(dst);

    let src_usage = m.state().mount.read_inode(src_ino).expect("src raw").i_blocks as u64 * 512;
    let dst_usage = m.state().mount.read_inode(dst_ino).expect("dst raw").i_blocks as u64 * 512;
    assert_ne!(src_usage, 0);
    assert_ne!(dst_usage, 0);
    let uq = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota before rename");
    let gq = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota before rename");
    assert_eq!(uq.dqb_curinodes, 2);
    assert_eq!(gq.dqb_curinodes, 2);
    assert_eq!(uq.dqb_curspace, src_usage + dst_usage);
    assert_eq!(gq.dqb_curspace, src_usage + dst_usage);

    m.state().rename_at(b"/ug-rename-src.txt", b"/ug-rename-dst.txt").expect("rename overwrite");

    let uq_after = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota after rename");
    let gq_after = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota after rename");
    assert_eq!(uq_after.dqb_curinodes, 1);
    assert_eq!(gq_after.dqb_curinodes, 1);
    assert_eq!(uq_after.dqb_curspace, src_usage);
    assert_eq!(gq_after.dqb_curspace, src_usage);
}

#[test]
fn chown_transfers_user_group_quota_usage() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_user_group_quota_disk()).expect("rw mount with hidden user/group quota");

    let inode = m.state().create_at(b"/ug-chown-transfer.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    inode.write(0, &vec![0x91; (bs * 2) as usize]).expect("write file");
    let charged = m.state().mount.read_inode(ino).expect("raw before chown").i_blocks as u64 * 512;

    assert_eq!(vfs::quota_getquota(&sb, Kqid::user(0)).expect("old user before").dqb_curspace, charged);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::group(0)).expect("old group before").dqb_curspace, charged);

    let mut ia = vfs::Iattr { valid: vfs::ATTR_UID | vfs::ATTR_GID, uid: 1000, gid: 1001, ..Default::default() };
    vfs::notify_change(&vfs::IDENTITY, &inode, &mut ia, &vfs::Cred::root()).expect("chown transfer");

    let raw = m.state().mount.read_inode(ino).expect("raw after chown");
    assert_eq!(raw.uid, 1000);
    assert_eq!(raw.gid, 1001);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::user(0)).expect("old user after").dqb_curspace, 0);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::group(0)).expect("old group after").dqb_curspace, 0);
    let new_user = vfs::quota_getquota(&sb, Kqid::user(1000)).expect("new user after");
    let new_group = vfs::quota_getquota(&sb, Kqid::group(1001)).expect("new group after");
    assert_eq!(new_user.dqb_curinodes, 1);
    assert_eq!(new_group.dqb_curinodes, 1);
    assert_eq!(new_user.dqb_curspace, charged);
    assert_eq!(new_group.dqb_curspace, charged);
}

#[test]
fn combined_size_chown_transfers_old_usage_then_releases_truncated_space_from_new_owner() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_user_group_quota_disk()).expect("rw mount with hidden user/group quota");

    let inode = m.state().create_at(b"/ug-size-chown.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    inode.write(0, &vec![0xC1; (bs * 3) as usize]).expect("write file");
    let before = m.state().mount.read_inode(ino).expect("raw before combined setattr");
    let final_space = bs;

    let mut ia = vfs::Iattr {
        valid: vfs::ATTR_SIZE | vfs::ATTR_UID | vfs::ATTR_GID,
        size: final_space,
        uid: 1000,
        gid: 1001,
        ..Default::default()
    };
    vfs::notify_change(&vfs::IDENTITY, &inode, &mut ia, &vfs::Cred::root()).expect("combined size/chown");

    let after = m.state().mount.read_inode(ino).expect("raw after combined setattr");
    assert_eq!(before.uid, 0);
    assert_eq!(before.gid, 0);
    assert_eq!(after.uid, 1000);
    assert_eq!(after.gid, 1001);
    assert_eq!(after.size, final_space);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::user(0)).expect("old user after").dqb_curspace, 0);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::group(0)).expect("old group after").dqb_curspace, 0);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::user(1000)).expect("new user after").dqb_curspace, after.i_blocks as u64 * 512);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::group(1001)).expect("new group after").dqb_curspace, after.i_blocks as u64 * 512);
}

#[test]
fn combined_size_chown_edquot_checks_pre_truncate_usage() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_user_group_quota_disk()).expect("rw mount with hidden user/group quota");

    let inode = m.state().create_at(b"/ug-size-chown-edquot.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xD1; (bs * 16) as usize]).expect("write file");
    let before = m.state().mount.read_inode(ino).expect("raw before combined setattr EDQUOT");
    inode.set_size(before.size);
    inode.set_blocks(before.i_blocks as u64);
    let before_old_uq = vfs::quota_getquota(&sb, Kqid::user(0)).expect("old user before");
    let before_old_gq = vfs::quota_getquota(&sb, Kqid::group(0)).expect("old group before");
    let post_shrink_limit = 1;
    assert!(before.i_blocks as u64 * 512 > post_shrink_limit);
    assert_eq!(inode.blocks() * 512, before.i_blocks as u64 * 512);
    vfs::quota_enable_limits(&sb, vfs::QuotaType::User).expect("enable user limits");
    vfs::quota_enable_limits(&sb, vfs::QuotaType::Group).expect("enable group limits");
    vfs::quota_setquota_masked(&sb, Kqid::user(1000), vfs::MemDqblk { dqb_bhardlimit: post_shrink_limit, ..vfs::MemDqblk::new() }, vfs::DQB_SPC_HARD, 0)
        .expect("set target user hardlimit");
    vfs::quota_setquota_masked(&sb, Kqid::group(1001), vfs::MemDqblk { dqb_bhardlimit: post_shrink_limit, ..vfs::MemDqblk::new() }, vfs::DQB_SPC_HARD, 0)
        .expect("set target group hardlimit");
    assert_eq!(vfs::quota_getquota(&sb, Kqid::user(1000)).expect("target user limit").dqb_bhardlimit, post_shrink_limit);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::group(1001)).expect("target group limit").dqb_bhardlimit, post_shrink_limit);

    let mut ia = vfs::Iattr {
        valid: vfs::ATTR_SIZE | vfs::ATTR_UID | vfs::ATTR_GID,
        size: 0,
        uid: 1000,
        gid: 1001,
        ..Default::default()
    };
    let err = vfs::notify_change(&vfs::IDENTITY, &inode, &mut ia, &vfs::Cred::root()).expect_err("pre-truncate transfer exceeds target quota");

    assert_eq!(err, VfsError::Edquot);
    let after = m.state().mount.read_inode(ino).expect("raw after combined setattr EDQUOT");
    assert_eq!(after.uid, before.uid);
    assert_eq!(after.gid, before.gid);
    assert_eq!(after.size, before.size);
    assert_eq!(after.i_blocks, before.i_blocks);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::user(0)).expect("old user after").dqb_curspace, before_old_uq.dqb_curspace);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::group(0)).expect("old group after").dqb_curspace, before_old_gq.dqb_curspace);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::user(1000)).expect("new user after").dqb_curspace, 0);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::group(1001)).expect("new group after").dqb_curspace, 0);
}

#[test]
fn combined_size_chown_truncate_inode_failure_keeps_owner_transfer_without_size_change() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_user_group_quota_disk()).expect("rw mount with hidden user/group quota");

    let inode = m.state().create_at(b"/ug-size-chown-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    inode.write(0, &vec![0xC2; (bs * 3) as usize]).expect("write file");
    let before = m.state().mount.read_inode(ino).expect("raw before combined setattr failure");
    let before_space = before.i_blocks as u64 * 512;

    m.state().mount.fail_inode_write_after_for_tests(1);
    let mut ia = vfs::Iattr {
        valid: vfs::ATTR_SIZE | vfs::ATTR_UID | vfs::ATTR_GID,
        size: bs,
        uid: 1000,
        gid: 1001,
        ..Default::default()
    };
    let err = vfs::notify_change(&vfs::IDENTITY, &inode, &mut ia, &vfs::Cred::root()).expect_err("truncate inode write failure");

    assert_eq!(err, VfsError::Eio);
    let after = m.state().mount.read_inode(ino).expect("raw after combined setattr failure");
    assert_eq!(after.uid, 1000);
    assert_eq!(after.gid, 1001);
    assert_eq!(after.size, before.size);
    assert_eq!(after.i_blocks, before.i_blocks);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::user(0)).expect("old user after failure").dqb_curspace, 0);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::group(0)).expect("old group after failure").dqb_curspace, 0);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::user(1000)).expect("new user after failure").dqb_curspace, before_space);
    assert_eq!(vfs::quota_getquota(&sb, Kqid::group(1001)).expect("new group after failure").dqb_curspace, before_space);
}

#[test]
fn final_unlink_inode_write_failure_preserves_user_group_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_user_group_quota_disk()).expect("rw mount with hidden user/group quota");

    let inode = m.state().create_at(b"/ug-unlink-rollback.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xA7; (bs * 2) as usize]).expect("write file");
    let before_raw = m.state().mount.read_inode(ino).expect("raw before unlink");
    let before_map = m.state().mount.extent_map(ino).expect("extent map before unlink");
    let before_free_blocks = m.state().mount.state_free_blocks();
    let before_free_inodes = m.state().mount.state_free_inodes();
    let before_uq = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota before unlink");
    let before_gq = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota before unlink");
    assert_eq!(before_uq.dqb_curinodes, 1);
    assert_eq!(before_gq.dqb_curinodes, 1);
    assert_eq!(before_uq.dqb_curspace, before_raw.i_blocks as u64 * 512);
    assert_eq!(before_gq.dqb_curspace, before_raw.i_blocks as u64 * 512);
    drop(inode);

    m.state().mount.fail_next_inode_write_for_tests();
    let err = m.state().unlink_at(b"/ug-unlink-rollback.txt").expect_err("injected unlink inode write failure");

    assert_eq!(err, VfsError::Eio);
    assert_eq!(m.state().lookup_path(b"/ug-unlink-rollback.txt"), Some(ino));
    assert_eq!(m.state().mount.state_free_blocks(), before_free_blocks);
    assert_eq!(m.state().mount.state_free_inodes(), before_free_inodes);
    let after_raw = m.state().mount.read_inode(ino).expect("raw after unlink failure");
    assert_eq!(after_raw.links_count, before_raw.links_count);
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks);
    assert_eq!(after_raw.size, before_raw.size);
    assert_eq!(m.state().mount.extent_map(ino).expect("extent map after unlink failure"), before_map);
    let after_uq = vfs::quota_getquota(&sb, Kqid::user(0)).expect("user quota after unlink failure");
    let after_gq = vfs::quota_getquota(&sb, Kqid::group(0)).expect("group quota after unlink failure");
    assert_eq!(after_uq.dqb_curinodes, before_uq.dqb_curinodes);
    assert_eq!(after_gq.dqb_curinodes, before_gq.dqb_curinodes);
    assert_eq!(after_uq.dqb_curspace, before_uq.dqb_curspace);
    assert_eq!(after_gq.dqb_curspace, before_gq.dqb_curspace);
}
