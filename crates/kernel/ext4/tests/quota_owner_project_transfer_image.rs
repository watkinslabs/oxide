extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{FileAttr, Kqid, MemDqblk, SuperBlock, VfsError};

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
const PRJ_QUOTA_INO: u32 = 12;
const USR_MAGIC: u32 = 0xd9c0_1f11;
const GRP_MAGIC: u32 = 0xd9c0_1927;
const PRJ_MAGIC: u32 = 0xd9c0_3f14;
const V2_VERSION_V1: u32 = 1;
const FS_NODUMP_FL: u32 = vfs::inode::FS_NODUMP_FL;

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

fn seeded_all_quota_disk() -> Arc<dyn BlockDevice> {
    let disk = shared_disk_from(IMAGE.to_vec());
    let m = ext4::rootfs::Ext4Mount::open(disk.clone()).expect("seed Ext4Mount::open");
    m.state().mount.init_inode(2, USR_QUOTA_INO, ext4::inode::S_IFREG | 0o600, 1, 0, 0).expect("init user quota inode");
    m.state().mount.init_inode(2, GRP_QUOTA_INO, ext4::inode::S_IFREG | 0o600, 1, 0, 0).expect("init group quota inode");
    m.state().mount.write_at(USR_QUOTA_INO, 0, &empty_quota_file(USR_MAGIC)).expect("seed user quota");
    m.state().mount.write_at(GRP_QUOTA_INO, 0, &empty_quota_file(GRP_MAGIC)).expect("seed group quota");
    m.state().mount.write_at(PRJ_QUOTA_INO, 0, &empty_quota_file(PRJ_MAGIC)).expect("seed project quota");
    drop(m);
    patch_or_u32(&disk, EXT4_RO_COMPAT_OFF, EXT4_FEATURE_RO_COMPAT_QUOTA | EXT4_FEATURE_RO_COMPAT_PROJECT);
    patch_u32(&disk, EXT4_USR_QUOTA_INUM_OFF, USR_QUOTA_INO);
    patch_u32(&disk, EXT4_GRP_QUOTA_INUM_OFF, GRP_QUOTA_INO);
    patch_u32(&disk, EXT4_PRJ_QUOTA_INUM_OFF, PRJ_QUOTA_INO);
    disk
}

fn mount_result(disk: Arc<dyn BlockDevice>) -> vfs::KResult<(Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>)> {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb_result(fs, root, 0xE471_0A11, String::from("ext4"))?;
    Ok((m, sb))
}

fn quota(sb: &SuperBlock, qid: Kqid) -> vfs::MemDqblk {
    vfs::quota_getquota(sb, qid).expect("quota record")
}

fn set_project(inode: &vfs::Inode, projid: u32) {
    let flags = inode.fileattr_get().expect("file attrs").flags;
    inode.fileattr_set(&FileAttr { flags, fsx_projid: projid, ..Default::default() }).expect("set project");
}

fn chown(inode: &Arc<vfs::Inode>, uid: u32, gid: u32) {
    let mut ia = vfs::Iattr { valid: vfs::ATTR_UID | vfs::ATTR_GID, uid, gid, ..Default::default() };
    vfs::notify_change(&vfs::IDENTITY, inode, &mut ia, &vfs::Cred::root()).expect("chown");
}

fn truncate_to(inode: &Arc<vfs::Inode>, size: u64) {
    let mut ia = vfs::Iattr { valid: vfs::ATTR_SIZE, size, ..Default::default() };
    vfs::notify_change(&vfs::IDENTITY, inode, &mut ia, &vfs::Cred::root()).expect("truncate");
}

fn enable_space_hardlimit(sb: &SuperBlock, qid: Kqid, hard: u64) {
    vfs::quota_setquota_masked(sb, qid, MemDqblk { dqb_bhardlimit: hard, ..MemDqblk::new() }, vfs::DQB_SPC_HARD, 0)
        .expect("set hardlimit");
    vfs::quota_enable_limits(sb, qid.kind).expect("enable limits");
}

#[test]
fn project_then_chown_moves_inode_and_space_to_independent_quota_records() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_all_quota_disk()).expect("rw mount with all hidden quotas");
    assert!(sb.s_dquot.is_enabled(vfs::QuotaType::User));
    assert!(sb.s_dquot.is_enabled(vfs::QuotaType::Group));
    assert!(sb.s_dquot.is_enabled(vfs::QuotaType::Project));

    let inode = m.state().create_at(b"/owner-project-transfer.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xA1; (bs * 4) as usize]).expect("write file");
    let charged = m.state().mount.read_inode(ino).expect("raw before transfer").i_blocks as u64 * 512;
    assert_ne!(charged, 0);

    assert_eq!(quota(&sb, Kqid::user(0)).dqb_curspace, charged);
    assert_eq!(quota(&sb, Kqid::group(0)).dqb_curspace, charged);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curspace, charged);

    set_project(&inode, 77);
    assert_eq!(m.state().mount.read_inode(ino).expect("raw after project").i_projid, 77);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curspace, 0);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curinodes, 0);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curspace, charged);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curinodes, 1);
    assert_eq!(quota(&sb, Kqid::user(0)).dqb_curspace, charged);
    assert_eq!(quota(&sb, Kqid::group(0)).dqb_curspace, charged);

    chown(&inode, 1000, 1001);
    let raw = m.state().mount.read_inode(ino).expect("raw after chown");
    assert_eq!(raw.uid, 1000);
    assert_eq!(raw.gid, 1001);
    assert_eq!(raw.i_projid, 77);
    assert_eq!(quota(&sb, Kqid::user(0)).dqb_curspace, 0);
    assert_eq!(quota(&sb, Kqid::group(0)).dqb_curspace, 0);
    assert_eq!(quota(&sb, Kqid::user(1000)).dqb_curspace, charged);
    assert_eq!(quota(&sb, Kqid::user(1000)).dqb_curinodes, 1);
    assert_eq!(quota(&sb, Kqid::group(1001)).dqb_curspace, charged);
    assert_eq!(quota(&sb, Kqid::group(1001)).dqb_curinodes, 1);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curspace, charged);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curinodes, 1);
}

#[test]
fn chown_then_project_then_truncate_keeps_space_on_new_owner_and_project() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_all_quota_disk()).expect("rw mount with all hidden quotas");
    let inode = m.state().create_at(b"/owner-project-truncate.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xB2; (bs * 4) as usize]).expect("write file");

    chown(&inode, 2000, 2001);
    assert_eq!(quota(&sb, Kqid::user(2000)).dqb_curspace, quota(&sb, Kqid::project(0)).dqb_curspace);
    assert_eq!(quota(&sb, Kqid::group(2001)).dqb_curspace, quota(&sb, Kqid::project(0)).dqb_curspace);

    set_project(&inode, 88);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curspace, 0);
    assert_eq!(quota(&sb, Kqid::project(88)).dqb_curspace, quota(&sb, Kqid::user(2000)).dqb_curspace);

    truncate_to(&inode, bs);
    let raw = m.state().mount.read_inode(ino).expect("raw after truncate");
    let final_space = raw.i_blocks as u64 * 512;
    assert_eq!(raw.uid, 2000);
    assert_eq!(raw.gid, 2001);
    assert_eq!(raw.i_projid, 88);
    assert_eq!(raw.size, bs);
    assert_eq!(quota(&sb, Kqid::user(2000)).dqb_curspace, final_space);
    assert_eq!(quota(&sb, Kqid::group(2001)).dqb_curspace, final_space);
    assert_eq!(quota(&sb, Kqid::project(88)).dqb_curspace, final_space);
    assert_eq!(quota(&sb, Kqid::project(88)).dqb_curinodes, 1);
}

#[test]
fn project_transfer_edquot_preserves_user_group_and_old_project_usage() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_all_quota_disk()).expect("rw mount with all hidden quotas");
    let inode = m.state().create_at(b"/project-transfer-edquot.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xC3; (bs * 4) as usize]).expect("write file");
    let charged = m.state().mount.read_inode(ino).expect("raw before failed project transfer").i_blocks as u64 * 512;
    assert_ne!(charged, 0);
    let old_u = quota(&sb, Kqid::user(0));
    let old_g = quota(&sb, Kqid::group(0));
    let old_p = quota(&sb, Kqid::project(0));
    let new_p = quota(&sb, Kqid::project(77));
    assert_eq!(old_u.dqb_curspace, charged);
    assert_eq!(old_g.dqb_curspace, charged);
    assert_eq!(old_p.dqb_curspace, charged);

    enable_space_hardlimit(&sb, Kqid::project(77), 1);
    assert_eq!(
        inode.fileattr_set(&FileAttr { flags: inode.fileattr_get().unwrap().flags, fsx_projid: 77, ..Default::default() }),
        Err(VfsError::Edquot)
    );

    let raw = m.state().mount.read_inode(ino).expect("raw after failed project transfer");
    assert_eq!(raw.i_projid, 0);
    assert_eq!(raw.uid, 0);
    assert_eq!(raw.gid, 0);
    assert_eq!(quota(&sb, Kqid::user(0)).dqb_curspace, old_u.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::user(0)).dqb_curinodes, old_u.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::group(0)).dqb_curspace, old_g.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::group(0)).dqb_curinodes, old_g.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curspace, old_p.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curinodes, old_p.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curspace, new_p.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curinodes, new_p.dqb_curinodes);
}

#[test]
fn fileattr_flags_persist_when_project_transfer_edquot_preserves_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_all_quota_disk()).expect("rw mount with all hidden quotas");
    let inode = m.state().create_at(b"/fileattr-project-edquot.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xC4; (bs * 4) as usize]).expect("write file");
    let flags = inode.fileattr_get().expect("attrs before edquot").flags;
    assert_eq!(flags & FS_NODUMP_FL, 0);
    let old_p = quota(&sb, Kqid::project(0));
    let new_p = quota(&sb, Kqid::project(77));

    enable_space_hardlimit(&sb, Kqid::project(77), 1);
    assert_eq!(
        inode.fileattr_set(&FileAttr { flags: flags | FS_NODUMP_FL, fsx_projid: 77, ..Default::default() }),
        Err(VfsError::Edquot)
    );

    let raw = m.state().mount.read_inode(ino).expect("raw after fileattr edquot");
    assert_ne!(raw.i_flags & FS_NODUMP_FL, 0);
    assert_ne!(inode.fileattr_get().expect("attrs after edquot").flags & FS_NODUMP_FL, 0);
    assert_eq!(raw.i_projid, 0);
    assert_eq!(inode.fileattr_get().expect("project after edquot").fsx_projid, 0);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curspace, old_p.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curinodes, old_p.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curspace, new_p.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curinodes, new_p.dqb_curinodes);
}

#[test]
fn chown_edquot_after_project_transfer_preserves_project_and_old_owner_usage() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_all_quota_disk()).expect("rw mount with all hidden quotas");
    let inode = m.state().create_at(b"/project-chown-edquot.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xD4; (bs * 4) as usize]).expect("write file");
    let charged = m.state().mount.read_inode(ino).expect("raw before project transfer").i_blocks as u64 * 512;
    assert_ne!(charged, 0);
    set_project(&inode, 88);
    let project_after = quota(&sb, Kqid::project(88));
    assert_eq!(project_after.dqb_curspace, charged);

    enable_space_hardlimit(&sb, Kqid::user(2000), 1);
    enable_space_hardlimit(&sb, Kqid::group(2001), 1);
    let mut ia = vfs::Iattr { valid: vfs::ATTR_UID | vfs::ATTR_GID, uid: 2000, gid: 2001, ..Default::default() };
    assert_eq!(
        vfs::notify_change(&vfs::IDENTITY, &inode, &mut ia, &vfs::Cred::root()),
        Err(VfsError::Edquot)
    );

    let raw = m.state().mount.read_inode(ino).expect("raw after failed chown");
    assert_eq!(raw.uid, 0);
    assert_eq!(raw.gid, 0);
    assert_eq!(raw.i_projid, 88);
    assert_eq!(quota(&sb, Kqid::user(0)).dqb_curspace, charged);
    assert_eq!(quota(&sb, Kqid::group(0)).dqb_curspace, charged);
    assert_eq!(quota(&sb, Kqid::user(2000)).dqb_curspace, 0);
    assert_eq!(quota(&sb, Kqid::group(2001)).dqb_curspace, 0);
    assert_eq!(quota(&sb, Kqid::project(88)).dqb_curspace, project_after.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::project(88)).dqb_curinodes, project_after.dqb_curinodes);
}

#[test]
fn project_transfer_dirty_failure_rolls_back_all_quota_records() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_all_quota_disk()).expect("rw mount with all hidden quotas");
    let inode = m.state().create_at(b"/project-transfer-dirty-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xE5; (bs * 4) as usize]).expect("write file");
    let charged = m.state().mount.read_inode(ino).expect("raw before dirty failure").i_blocks as u64 * 512;
    assert_ne!(charged, 0);
    let old_u = quota(&sb, Kqid::user(0));
    let old_g = quota(&sb, Kqid::group(0));
    let old_p = quota(&sb, Kqid::project(0));
    let new_p = quota(&sb, Kqid::project(77));

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    assert_eq!(
        inode.fileattr_set(&FileAttr { flags: inode.fileattr_get().unwrap().flags, fsx_projid: 77, ..Default::default() }),
        Err(VfsError::Eio)
    );

    let raw = m.state().mount.read_inode(ino).expect("raw after failed project dirty");
    assert_eq!(raw.i_projid, 0);
    assert_eq!(inode.fileattr_get().expect("attrs after failed project dirty").fsx_projid, 0);
    assert_eq!(quota(&sb, Kqid::user(0)).dqb_curspace, old_u.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::user(0)).dqb_curinodes, old_u.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::group(0)).dqb_curspace, old_g.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::group(0)).dqb_curinodes, old_g.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curspace, old_p.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curinodes, old_p.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curspace, new_p.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curinodes, new_p.dqb_curinodes);
}

#[test]
fn fileattr_flags_persist_when_project_transfer_dirty_failure_preserves_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_all_quota_disk()).expect("rw mount with all hidden quotas");
    let inode = m.state().create_at(b"/fileattr-project-dirty-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xE6; (bs * 4) as usize]).expect("write file");
    let flags = inode.fileattr_get().expect("attrs before dirty failure").flags;
    assert_eq!(flags & FS_NODUMP_FL, 0);
    let old_p = quota(&sb, Kqid::project(0));
    let new_p = quota(&sb, Kqid::project(77));

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    assert_eq!(
        inode.fileattr_set(&FileAttr { flags: flags | FS_NODUMP_FL, fsx_projid: 77, ..Default::default() }),
        Err(VfsError::Eio)
    );

    let raw = m.state().mount.read_inode(ino).expect("raw after fileattr dirty failure");
    assert_ne!(raw.i_flags & FS_NODUMP_FL, 0);
    assert_ne!(inode.fileattr_get().expect("attrs after dirty failure").flags & FS_NODUMP_FL, 0);
    assert_eq!(raw.i_projid, 0);
    assert_eq!(inode.fileattr_get().expect("project after dirty failure").fsx_projid, 0);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curspace, old_p.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curinodes, old_p.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curspace, new_p.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curinodes, new_p.dqb_curinodes);
}

#[test]
fn chown_dirty_failure_after_project_transfer_rolls_back_owner_only() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_all_quota_disk()).expect("rw mount with all hidden quotas");
    let inode = m.state().create_at(b"/project-chown-dirty-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xF6; (bs * 4) as usize]).expect("write file");
    let charged = m.state().mount.read_inode(ino).expect("raw before project transfer").i_blocks as u64 * 512;
    assert_ne!(charged, 0);
    set_project(&inode, 88);
    let old_u = quota(&sb, Kqid::user(0));
    let old_g = quota(&sb, Kqid::group(0));
    let project_after = quota(&sb, Kqid::project(88));
    let new_u = quota(&sb, Kqid::user(2000));
    let new_g = quota(&sb, Kqid::group(2001));
    assert_eq!(project_after.dqb_curspace, charged);

    m.state().mount.fail_next_quota_mark_dirty_for_tests();
    let mut ia = vfs::Iattr { valid: vfs::ATTR_UID | vfs::ATTR_GID, uid: 2000, gid: 2001, ..Default::default() };
    assert_eq!(
        vfs::notify_change(&vfs::IDENTITY, &inode, &mut ia, &vfs::Cred::root()),
        Err(VfsError::Eio)
    );

    let raw = m.state().mount.read_inode(ino).expect("raw after failed chown dirty");
    assert_eq!(raw.uid, 0);
    assert_eq!(raw.gid, 0);
    assert_eq!(raw.i_projid, 88);
    assert_eq!(quota(&sb, Kqid::user(0)).dqb_curspace, old_u.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::user(0)).dqb_curinodes, old_u.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::group(0)).dqb_curspace, old_g.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::group(0)).dqb_curinodes, old_g.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::user(2000)).dqb_curspace, new_u.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::user(2000)).dqb_curinodes, new_u.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::group(2001)).dqb_curspace, new_g.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::group(2001)).dqb_curinodes, new_g.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::project(88)).dqb_curspace, project_after.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::project(88)).dqb_curinodes, project_after.dqb_curinodes);
}

#[test]
fn project_persist_failure_retries_quota_transfer_rollback() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_all_quota_disk()).expect("rw mount with all hidden quotas");
    let inode = m.state().create_at(b"/project-persist-rollback-retry.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xA7; (bs * 4) as usize]).expect("write file");
    let charged = m.state().mount.read_inode(ino).expect("raw before project persist failure").i_blocks as u64 * 512;
    let old_p = quota(&sb, Kqid::project(0));
    let new_p = quota(&sb, Kqid::project(77));
    assert_eq!(old_p.dqb_curspace, charged);
    assert_eq!(new_p.dqb_curspace, 0);

    m.state().mount.fail_inode_write_after_for_tests(1);
    m.state().mount.fail_quota_mark_dirty_after_for_tests(3);
    assert_eq!(
        inode.fileattr_set(&FileAttr { flags: inode.fileattr_get().unwrap().flags, fsx_projid: 77, ..Default::default() }),
        Err(VfsError::Eio)
    );

    let raw = m.state().mount.read_inode(ino).expect("raw after project persist failure");
    assert_eq!(raw.i_projid, 0);
    assert_eq!(inode.fileattr_get().expect("attrs after project rollback retry").fsx_projid, 0);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curspace, old_p.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curinodes, old_p.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curspace, new_p.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curinodes, new_p.dqb_curinodes);
}

#[test]
fn fileattr_flags_persist_when_project_persist_failure_rolls_back_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_all_quota_disk()).expect("rw mount with all hidden quotas");
    let inode = m.state().create_at(b"/fileattr-project-persist-fail.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xA8; (bs * 4) as usize]).expect("write file");
    let flags = inode.fileattr_get().expect("attrs before persist failure").flags;
    let old_p = quota(&sb, Kqid::project(0));
    let new_p = quota(&sb, Kqid::project(77));

    m.state().mount.fail_inode_write_after_for_tests(1);
    assert_eq!(
        inode.fileattr_set(&FileAttr { flags: flags | FS_NODUMP_FL, fsx_projid: 77, ..Default::default() }),
        Err(VfsError::Eio)
    );

    let raw = m.state().mount.read_inode(ino).expect("raw after fileattr persist failure");
    assert_ne!(raw.i_flags & FS_NODUMP_FL, 0);
    assert_eq!(raw.i_projid, 0);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curspace, old_p.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::project(0)).dqb_curinodes, old_p.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curspace, new_p.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::project(77)).dqb_curinodes, new_p.dqb_curinodes);
}

#[test]
fn chown_persist_failure_retries_quota_transfer_rollback() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_all_quota_disk()).expect("rw mount with all hidden quotas");
    let inode = m.state().create_at(b"/chown-persist-rollback-retry.txt", 0o644).expect("create file");
    let ino = inode.ino() as u32;
    let bs = m.state().mount.sb.block_size as u64;
    m.state().mount.write_at(ino, 0, &vec![0xB8; (bs * 4) as usize]).expect("write file");
    let charged = m.state().mount.read_inode(ino).expect("raw before chown persist failure").i_blocks as u64 * 512;
    let old_u = quota(&sb, Kqid::user(0));
    let old_g = quota(&sb, Kqid::group(0));
    let new_u = quota(&sb, Kqid::user(2000));
    let new_g = quota(&sb, Kqid::group(2001));
    assert_eq!(old_u.dqb_curspace, charged);
    assert_eq!(old_g.dqb_curspace, charged);

    m.state().mount.fail_next_inode_write_for_tests();
    m.state().mount.fail_quota_mark_dirty_after_for_tests(5);
    let mut ia = vfs::Iattr { valid: vfs::ATTR_UID | vfs::ATTR_GID, uid: 2000, gid: 2001, ..Default::default() };
    assert_eq!(
        vfs::notify_change(&vfs::IDENTITY, &inode, &mut ia, &vfs::Cred::root()),
        Err(VfsError::Eio)
    );

    let raw = m.state().mount.read_inode(ino).expect("raw after chown persist failure");
    assert_eq!(raw.uid, 0);
    assert_eq!(raw.gid, 0);
    assert_eq!(inode.uid().expect("uid after chown rollback retry"), 0);
    assert_eq!(inode.gid().expect("gid after chown rollback retry"), 0);
    assert_eq!(quota(&sb, Kqid::user(0)).dqb_curspace, old_u.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::user(0)).dqb_curinodes, old_u.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::group(0)).dqb_curspace, old_g.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::group(0)).dqb_curinodes, old_g.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::user(2000)).dqb_curspace, new_u.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::user(2000)).dqb_curinodes, new_u.dqb_curinodes);
    assert_eq!(quota(&sb, Kqid::group(2001)).dqb_curspace, new_g.dqb_curspace);
    assert_eq!(quota(&sb, Kqid::group(2001)).dqb_curinodes, new_g.dqb_curinodes);
}
