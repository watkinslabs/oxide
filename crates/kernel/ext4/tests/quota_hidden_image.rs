extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::superblock::SB_RDONLY;
use vfs::{Kqid, MemDqblk, SuperBlock};

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
const EXT4_RO_COMPAT_OFF: usize = EXT4_SUPERBLOCK_OFFSET + 0x64;
const EXT4_PRJ_QUOTA_INUM_OFF: usize = EXT4_SUPERBLOCK_OFFSET + ext4::superblock::SB_OFF_PRJ_QUOTA_INUM;
const EXT4_FEATURE_RO_COMPAT_QUOTA: u32 = 0x0100;
const EXT4_FEATURE_RO_COMPAT_PROJECT: u32 = ext4::superblock::RO_COMPAT_PROJECT;
const HELLO_INO: u32 = 12;
const PRJ_MAGIC: u32 = 0xd9c0_3f14;
const V2_VERSION_V1: u32 = 1;
const V2_VERSION_V0: u32 = 0;
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

fn seeded_quota_disk() -> Arc<dyn BlockDevice> {
    // Seed the hidden inode before setting the quota feature: mount-time
    // realization must consume an already valid on-disk quota file.
    let disk = shared_disk_from(IMAGE.to_vec());
    let m = ext4::rootfs::Ext4Mount::open(disk.clone()).expect("seed Ext4Mount::open");
    m.state().mount.write_at(HELLO_INO, 0, &empty_project_quota_file()).expect("seed quota file");
    drop(m);
    patch_u32(&disk, EXT4_RO_COMPAT_OFF, EXT4_FEATURE_RO_COMPAT_QUOTA | EXT4_FEATURE_RO_COMPAT_PROJECT);
    patch_u32(&disk, EXT4_PRJ_QUOTA_INUM_OFF, HELLO_INO);
    disk
}

fn quota_disk() -> Arc<dyn BlockDevice> {
    let mut image = IMAGE.to_vec();
    let mut features = u32::from_le_bytes(image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4].try_into().unwrap());
    features |= EXT4_FEATURE_RO_COMPAT_PROJECT;
    image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4].copy_from_slice(&features.to_le_bytes());
    image[EXT4_PRJ_QUOTA_INUM_OFF..EXT4_PRJ_QUOTA_INUM_OFF + 4].copy_from_slice(&HELLO_INO.to_le_bytes());
    shared_disk_from(image)
}

fn quota_disk_with_project_inode(ino: u32) -> Arc<dyn BlockDevice> {
    let mut image = IMAGE.to_vec();
    let mut features = u32::from_le_bytes(image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4].try_into().unwrap());
    features |= EXT4_FEATURE_RO_COMPAT_PROJECT;
    image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4].copy_from_slice(&features.to_le_bytes());
    image[EXT4_PRJ_QUOTA_INUM_OFF..EXT4_PRJ_QUOTA_INUM_OFF + 4].copy_from_slice(&ino.to_le_bytes());
    shared_disk_from(image)
}

fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_F1A6, String::from("ext4"));
    (m, sb)
}

fn mount_result(disk: Arc<dyn BlockDevice>) -> vfs::KResult<(Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>)> {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb_result(fs, root, 0xE471_F1A6, String::from("ext4"))?;
    Ok((m, sb))
}

fn mount_readonly_result(disk: Arc<dyn BlockDevice>) -> vfs::KResult<(Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>)> {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb_readonly_result(fs, root, 0xE471_F1A6, String::from("ext4"))?;
    Ok((m, sb))
}

fn empty_project_quota_file() -> Vec<u8> {
    empty_project_quota_file_version(V2_VERSION_V1)
}

fn empty_project_quota_file_version(version: u32) -> Vec<u8> {
    let mut q = vec![0u8; 2048];
    q[0..4].copy_from_slice(&PRJ_MAGIC.to_le_bytes());
    q[4..8].copy_from_slice(&version.to_le_bytes());
    q[20..24].copy_from_slice(&2u32.to_le_bytes());
    q
}

#[test]
fn hidden_project_quota_auto_activates_at_rw_mount() {
    common::boot_hosted_pmm();
    let (_m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let kind = vfs::QuotaType::Project;
    assert!(sb.s_dquot.is_enabled(kind), "hidden quota accounting enabled at mount");
    assert_eq!(vfs::quota_getfmt(&sb, kind).expect("auto quota format"), vfs::QFMT_VFS_V1);
    assert_eq!(vfs::quota_getinfo(&sb, kind).expect("auto quota info").dqi_flags & vfs::DQF_SYS_FILE, vfs::DQF_SYS_FILE);
    assert!(!sb.s_dquot.is_enforced(kind), "mount-time hidden quota leaves limits disabled");
}

#[test]
fn hidden_project_quota_does_not_auto_activate_at_ro_mount() {
    common::boot_hosted_pmm();
    let (_m, sb) = mount_readonly_result(seeded_quota_disk()).expect("ro mount with hidden quota");
    let kind = vfs::QuotaType::Project;
    assert!(sb.is_readonly(), "fixture mounted read-only");
    assert!(!sb.s_dquot.is_enabled(kind), "read-only mount leaves hidden quota inactive");
    assert_eq!(vfs::quota_getfmt(&sb, kind), Err(vfs::VfsError::Esrch));
}

#[test]
fn hidden_project_quota_auto_activates_at_ro_to_rw_remount() {
    common::boot_hosted_pmm();
    let (_m, sb) = mount_readonly_result(seeded_quota_disk()).expect("ro mount with hidden quota");
    let kind = vfs::QuotaType::Project;
    assert!(sb.is_readonly(), "fixture starts read-only");
    assert!(!sb.s_dquot.is_enabled(kind), "RO mount leaves hidden quota inactive");

    sb.reconfigure_super(0, SB_RDONLY, "").expect("RO→RW remount enables hidden quota");

    assert!(!sb.is_readonly(), "RO→RW remount clears SB_RDONLY");
    assert!(sb.s_dquot.is_enabled(kind), "hidden quota accounting enabled by remount");
    assert_eq!(vfs::quota_getfmt(&sb, kind).expect("remount quota format"), vfs::QFMT_VFS_V1);
    assert_eq!(vfs::quota_getinfo(&sb, kind).expect("remount quota info").dqi_flags & vfs::DQF_SYS_FILE, vfs::DQF_SYS_FILE);
    assert!(!sb.s_dquot.is_enforced(kind), "remount hidden quota leaves limits disabled");
}

#[test]
fn hidden_project_quota_failure_aborts_ro_to_rw_remount() {
    common::boot_hosted_pmm();
    let disk = quota_disk();
    patch_u32(&disk, EXT4_RO_COMPAT_OFF, EXT4_FEATURE_RO_COMPAT_QUOTA | EXT4_FEATURE_RO_COMPAT_PROJECT);
    patch_u32(&disk, EXT4_PRJ_QUOTA_INUM_OFF, HELLO_INO);
    let (_m, sb) = mount_readonly_result(disk).expect("RO mount with invalid hidden quota");
    let kind = vfs::QuotaType::Project;
    assert!(sb.is_readonly(), "fixture starts read-only");

    assert_eq!(sb.reconfigure_super(0, SB_RDONLY, ""), Err(vfs::VfsError::Einval));

    assert!(sb.is_readonly(), "failed RO→RW remount leaves SB_RDONLY set");
    assert!(!sb.s_dquot.is_enabled(kind), "failed remount leaves hidden quota inactive");
}

#[test]
fn project_block_quota_edquot_write_does_not_leak_allocated_block() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    vfs::quota_setquota(&sb, qid, MemDqblk { dqb_bhardlimit: 1, dqb_ihardlimit: 100, ..MemDqblk::new() })
        .expect("set tiny block quota");
    vfs::quota_enable_limits(&sb, vfs::QuotaType::Project).expect("enable project limits");

    let inode = m.state().create_at(b"/edquot.txt", 0o644).expect("create empty file");
    let ino = inode.ino() as u32;
    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");

    assert!(m.state().mount.write_at(ino, 0, &[0x5a]).is_err(), "write must fail with EDQUOT");

    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    assert_eq!(m.state().mount.state_free_blocks(), before_free, "EDQUOT write must not leak a block");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks, "EDQUOT write must not charge i_blocks");
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after failed write").dqb_curspace, 0);
}

#[test]
fn project_block_quota_edquot_xattr_external_block_does_not_leak() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    vfs::quota_setquota(&sb, qid, MemDqblk { dqb_bhardlimit: 1, dqb_ihardlimit: 100, ..MemDqblk::new() })
        .expect("set tiny block quota");
    vfs::quota_enable_limits(&sb, vfs::QuotaType::Project).expect("enable project limits");

    let inode = m.state().create_at(b"/xattr-edquot.txt", 0o644).expect("create empty file");
    let ino = inode.ino() as u32;
    let before_free = m.state().mount.state_free_blocks();
    let before_raw = m.state().mount.read_inode(ino).expect("raw before");
    let big = vec![0xAB; 200];

    assert!(m.state().mount.store_xattrs(ino, &[(String::from("user.big"), big)]).is_err(),
        "external xattr block allocation must fail with EDQUOT");

    let after_raw = m.state().mount.read_inode(ino).expect("raw after");
    assert_eq!(m.state().mount.state_free_blocks(), before_free, "EDQUOT xattr must not leak a block");
    assert_eq!(after_raw.i_blocks, before_raw.i_blocks, "EDQUOT xattr must not charge i_blocks");
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after failed xattr").dqb_curspace, 0);
}

#[test]
fn tmpfile_orphan_free_releases_project_inode_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let root = m.state().lookup_inode_any(b"/").expect("lookup root");
    let tmp = root.tmpfile(0o600, &vfs::CreateCtx::root()).expect("tmpfile");
    let ino = tmp.ino() as u32;

    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after tmpfile").dqb_curinodes, 1);

    drop(tmp);
    m.state().free_orphan_inode(ino).expect("free orphan");
    m.state().orphan_remove(ino);

    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after orphan free").dqb_curinodes, 0);
}

#[test]
fn legacy_anonymous_create_charges_project_inode_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    let tmp = m.state().create_anonymous_at(b"/", 0o600).expect("anonymous create");
    let ino = tmp.ino() as u32;

    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after anonymous create").dqb_curinodes, 1);

    drop(tmp);
    m.state().free_orphan_inode(ino).expect("free orphan");
    m.state().orphan_remove(ino);

    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after anonymous free").dqb_curinodes, 0);
}

#[test]
fn rename_overwrite_releases_replaced_project_quota_usage() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(0);
    m.state().create_at(b"/rename-src.txt", 0o644).expect("create source");
    let dst = m.state().create_at(b"/rename-dst.txt", 0o644).expect("create dest");
    let dst_ino = dst.ino() as u32;
    m.state().mount.write_at(dst_ino, 0, &[0x5a]).expect("write dest");
    let dst_usage = m.state().mount.read_inode(dst_ino).expect("dst raw").i_blocks as u64 * 512;
    assert_ne!(dst_usage, 0);

    let before = vfs::quota_getquota(&sb, qid).expect("quota before rename");
    assert_eq!(before.dqb_curinodes, 2);
    assert_eq!(before.dqb_curspace, dst_usage);

    m.state().rename_at(b"/rename-src.txt", b"/rename-dst.txt").expect("rename overwrite");

    // `dst` still holds the replaced victim. Rename over an existing target
    // only decrements the victim's link count and orphans it — no quota
    // release — so the charge lives until the inode is freed at eviction.
    let held = vfs::quota_getquota(&sb, qid).expect("quota after rename while victim held");
    assert_eq!(held.dqb_curinodes, 2, "the overwritten victim stays charged while held");
    assert_eq!(held.dqb_curspace, dst_usage);

    vfs::file::iput(dst);
    let after = vfs::quota_getquota(&sb, qid).expect("quota after victim eviction");
    assert_eq!(after.dqb_curinodes, 1);
    assert_eq!(after.dqb_curspace, 0);
}

#[test]
fn hidden_project_quota_failure_aborts_mount_realization() {
    common::boot_hosted_pmm();
    let disk = quota_disk();
    patch_u32(&disk, EXT4_RO_COMPAT_OFF, EXT4_FEATURE_RO_COMPAT_QUOTA | EXT4_FEATURE_RO_COMPAT_PROJECT);
    patch_u32(&disk, EXT4_PRJ_QUOTA_INUM_OFF, HELLO_INO);
    assert!(matches!(mount_result(disk), Err(vfs::VfsError::Einval)), "invalid hidden quota blocks mount");
}

#[test]
fn hidden_project_quota_rejects_bad_superblock_quota_inode_number() {
    common::boot_hosted_pmm();
    let (_m, sb) = mount(quota_disk_with_project_inode(4));
    assert_eq!(sb.s_op.quota_on(&sb, vfs::QuotaType::Project, 0, None), Err(vfs::VfsError::Euclean));
}

#[test]
fn hidden_project_quota_rejects_readonly_superblock_like_linux() {
    common::boot_hosted_pmm();
    let disk = quota_disk();
    let (m, sb) = mount(disk);
    m.state().mount.write_at(HELLO_INO, 0, &empty_project_quota_file()).expect("seed quota file");
    sb.set_readonly(true);
    assert_eq!(sb.s_op.quota_on(&sb, vfs::QuotaType::Project, 0, None), Err(vfs::VfsError::Erofs));
}

#[test]
fn hidden_project_quota_inserts_new_qtree_record_and_reloads() {
    common::boot_hosted_pmm();
    let disk = quota_disk();
    let (m, sb) = mount(disk.clone());
    assert_eq!(m.state().mount.lookup_path(b"/hello.txt").expect("hello"), HELLO_INO);
    m.state().mount.write_at(HELLO_INO, 0, &empty_project_quota_file()).expect("seed quota file");

    sb.s_op.quota_on(&sb, vfs::QuotaType::Project, 0, None).expect("quota_on");
    assert_eq!(vfs::quota_getfmt(&sb, vfs::QuotaType::Project).expect("fmt"), vfs::QFMT_VFS_V1);
    assert_eq!(vfs::quota_getinfo(&sb, vfs::QuotaType::Project).expect("info").dqi_flags & vfs::DQF_SYS_FILE, vfs::DQF_SYS_FILE);
    let qid = Kqid::project(42);
    let want = MemDqblk {
        dqb_bhardlimit: 8 * 1024,
        dqb_bsoftlimit: 4 * 1024,
        dqb_curspace:   1024,
        dqb_ihardlimit: 9,
        dqb_isoftlimit: 7,
        dqb_curinodes:  3,
        dqb_btime:      11,
        dqb_itime:      13,
        ..MemDqblk::new()
    };
    vfs::quota_setquota(&sb, qid, want).expect("setquota");
    vfs::quota_sync(&sb, vfs::QuotaType::Project).expect("sync quota");
    vfs::quota_off(&sb, vfs::QuotaType::Project).expect("quota_off");
    drop(sb); drop(m);

    let (_m2, sb2) = mount(disk.clone());
    sb2.s_op.quota_on(&sb2, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, None).expect("quota_on remount");
    let (next, next_blk) = vfs::quota_getnextquota(&sb2, Kqid::project(1)).expect("getnext after remount");
    assert_eq!(next, qid);
    assert_eq!(next_blk.dqb_curspace, want.dqb_curspace);
    let got = vfs::quota_getquota(&sb2, qid).expect("getquota after remount");
    assert_eq!(got.dqb_bhardlimit, want.dqb_bhardlimit);
    assert_eq!(got.dqb_bsoftlimit, want.dqb_bsoftlimit);
    assert_eq!(got.dqb_curspace, want.dqb_curspace);
    assert_eq!(got.dqb_ihardlimit, want.dqb_ihardlimit);
    assert_eq!(got.dqb_isoftlimit, want.dqb_isoftlimit);
    assert_eq!(got.dqb_curinodes, want.dqb_curinodes);
    assert_eq!(got.dqb_btime, want.dqb_btime);
    assert_eq!(got.dqb_itime, want.dqb_itime);

    vfs::quota_setquota(&sb2, qid, MemDqblk::new()).expect("clear quota");
    vfs::quota_sync(&sb2, vfs::QuotaType::Project).expect("sync clear");
    vfs::quota_off(&sb2, vfs::QuotaType::Project).expect("quota_off clear");
    drop(sb2);

    let (_m3, sb3) = mount(disk);
    sb3.s_op.quota_on(&sb3, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, None).expect("quota_on final");
    assert_eq!(vfs::quota_getnextquota(&sb3, qid), Err(vfs::VfsError::Enoent));
}

#[test]
fn named_project_quota_file_persists_outside_hidden_inode() {
    common::boot_hosted_pmm();
    let disk = quota_disk();
    let (m, sb) = mount(disk.clone());
    let qfile = m.state().create_at(b"/visible.quota", 0o600).expect("create visible quota");
    m.state().mount.write_at(HELLO_INO, 0, &empty_project_quota_file()).expect("seed hidden quota");
    m.state().mount.write_at(qfile.ino() as u32, 0, &empty_project_quota_file()).expect("seed visible quota");
    let root = sb.s_root().expect("root dentry");
    let qpath = vfs::path_lookup_path(root.clone(), root, "/visible.quota", vfs::LookupFlags::default()).expect("resolve visible quota");
    let raw_before_on = m.state().mount.read_inode(qfile.ino() as u32).expect("raw quota inode before on");

    sb.s_op.quota_on(&sb, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, Some(&qpath)).expect("quota_on visible");
    assert_eq!(vfs::quota_getinfo(&sb, vfs::QuotaType::Project).expect("visible info").dqi_flags & vfs::DQF_SYS_FILE, 0);
    assert_ne!(qfile.i_flags() & vfs::S_IMMUTABLE, 0, "quota file marked immutable");
    assert_ne!(qfile.i_flags() & vfs::S_NOATIME, 0, "quota file marked noatime");
    let raw_before_off = m.state().mount.read_inode(qfile.ino() as u32).expect("raw quota inode after on");
    assert_ne!(raw_before_off.i_flags & FS_IMMUTABLE_FL, 0, "quota_on persists immutable flag");
    assert_ne!(raw_before_off.i_flags & FS_NOATIME_FL, 0, "quota_on persists noatime flag");
    assert_eq!(raw_before_off.mtime, raw_before_on.mtime, "quota_on does not update visible quota-file mtime");
    assert_eq!(raw_before_off.ctime, raw_before_on.ctime, "quota_on does not update visible quota-file ctime");
    let qid = Kqid::project(77);
    let want = MemDqblk {
        dqb_bhardlimit: 16 * 1024,
        dqb_bsoftlimit: 12 * 1024,
        dqb_curspace:   2048,
        dqb_ihardlimit: 19,
        dqb_isoftlimit: 17,
        dqb_curinodes:  5,
        dqb_btime:      23,
        dqb_itime:      29,
        ..MemDqblk::new()
    };
    vfs::quota_setquota(&sb, qid, want).expect("setquota visible");
    vfs::quota_sync(&sb, vfs::QuotaType::Project).expect("sync visible");
    vfs::quota_off(&sb, vfs::QuotaType::Project).expect("quota_off visible");
    assert_eq!(qfile.i_flags() & (vfs::S_IMMUTABLE | vfs::S_NOATIME), 0, "quota_off clears visible quota-file flags");
    let raw_after_off = m.state().mount.read_inode(qfile.ino() as u32).expect("raw quota inode after off");
    assert_eq!(raw_after_off.i_flags & (FS_IMMUTABLE_FL | FS_NOATIME_FL), 0, "quota_off persists visible quota-file flag clear");
    assert!(raw_after_off.mtime >= raw_before_off.mtime, "quota_off updates visible quota-file mtime");
    assert!(raw_after_off.ctime >= raw_before_off.ctime, "quota_off updates visible quota-file ctime");
    drop(sb); drop(m);

    let (_m2, sb2) = mount(disk.clone());
    sb2.s_op.quota_on(&sb2, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, None).expect("quota_on hidden");
    assert_eq!(vfs::quota_getnextquota(&sb2, qid), Err(vfs::VfsError::Enoent), "hidden quota inode must not receive visible-file updates");
    vfs::quota_off(&sb2, vfs::QuotaType::Project).expect("quota_off hidden");
    drop(sb2);

    let (m3, sb3) = mount(disk);
    let root3 = sb3.s_root().expect("root dentry remount");
    let qpath3 = vfs::path_lookup_path(root3.clone(), root3, "/visible.quota", vfs::LookupFlags::default()).expect("resolve visible remount");
    assert_eq!(m3.state().mount.lookup_path(b"/visible.quota").expect("visible lookup"), qpath3.inode.ino() as u32);
    sb3.s_op.quota_on(&sb3, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, Some(&qpath3)).expect("quota_on visible remount");
    let got = vfs::quota_getquota(&sb3, qid).expect("getquota visible remount");
    assert_eq!(got.dqb_bhardlimit, want.dqb_bhardlimit);
    assert_eq!(got.dqb_bsoftlimit, want.dqb_bsoftlimit);
    assert_eq!(got.dqb_curspace, want.dqb_curspace);
    assert_eq!(got.dqb_ihardlimit, want.dqb_ihardlimit);
    assert_eq!(got.dqb_isoftlimit, want.dqb_isoftlimit);
    assert_eq!(got.dqb_curinodes, want.dqb_curinodes);
    assert_eq!(got.dqb_btime, want.dqb_btime);
    assert_eq!(got.dqb_itime, want.dqb_itime);
}

#[test]
fn named_project_quota_file_growth_is_not_quota_accounted_to_itself() {
    common::boot_hosted_pmm();
    let (m, sb) = mount(quota_disk());
    let qfile = m.state().create_at(b"/visible-grow.quota", 0o600).expect("create visible quota");
    let qino = qfile.ino() as u32;
    m.state().mount.write_at(qino, 0, &empty_project_quota_file()).expect("seed visible quota");
    let root = sb.s_root().expect("root dentry");
    let qpath = vfs::path_lookup_path(root.clone(), root, "/visible-grow.quota", vfs::LookupFlags::default()).expect("resolve visible quota");
    sb.s_op.quota_on(&sb, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, Some(&qpath)).expect("quota_on visible");

    let owner = Kqid::project(0);
    let before_quota = vfs::quota_getquota(&sb, owner).expect("owner quota before visible write");
    let before_blocks = m.state().mount.read_inode(qino).expect("raw visible quota before write").i_blocks;
    vfs::quota_setquota(&sb, Kqid::project(88), MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).expect("dirty new visible record");
    vfs::quota_sync(&sb, vfs::QuotaType::Project).expect("sync visible quota file");

    let after_blocks = m.state().mount.read_inode(qino).expect("raw visible quota after write").i_blocks;
    assert!(after_blocks > before_blocks, "first qtree insert grows the visible quota file");
    let after_quota = vfs::quota_getquota(&sb, owner).expect("owner quota after visible write");
    assert_eq!(after_quota.dqb_curspace, before_quota.dqb_curspace);
    assert_eq!(after_quota.dqb_curinodes, before_quota.dqb_curinodes);
}

#[test]
fn named_project_quota_file_rejects_encrypted_inode_like_linux() {
    common::boot_hosted_pmm();
    let disk = quota_disk();
    let (m, sb) = mount(disk);
    let qfile = m.state().create_at(b"/visible-encrypted.quota", 0o600).expect("create visible quota");
    m.state().mount.write_at(qfile.ino() as u32, 0, &empty_project_quota_file()).expect("seed visible quota");
    qfile.set_i_flags(qfile.i_flags() | vfs::inode::S_ENCRYPTED);
    let root = sb.s_root().expect("root dentry");
    let qpath = vfs::path_lookup_path(root.clone(), root, "/visible-encrypted.quota", vfs::LookupFlags::default()).expect("resolve visible quota");
    assert_eq!(sb.s_op.quota_on(&sb, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, Some(&qpath)), Err(vfs::VfsError::Einval));
}

#[test]
fn hidden_project_quota_v0_uses_v2r0_records() {
    common::boot_hosted_pmm();
    let disk = quota_disk();
    let (m, sb) = mount(disk.clone());
    m.state().mount.write_at(HELLO_INO, 0, &empty_project_quota_file_version(V2_VERSION_V0)).expect("seed v0 quota file");

    sb.s_op.quota_on(&sb, vfs::QuotaType::Project, 0, None).expect("quota_on v0");
    assert_eq!(vfs::quota_getfmt(&sb, vfs::QuotaType::Project).expect("fmt"), vfs::QFMT_VFS_V0);
    let qid = Kqid::project(55);
    let want = MemDqblk {
        dqb_bhardlimit: 32 * 1024,
        dqb_bsoftlimit: 24 * 1024,
        dqb_curspace:   4096,
        dqb_ihardlimit: 33,
        dqb_isoftlimit: 31,
        dqb_curinodes:  7,
        dqb_btime:      37,
        dqb_itime:      41,
        ..MemDqblk::new()
    };
    vfs::quota_setquota(&sb, qid, want).expect("setquota v0");
    vfs::quota_sync(&sb, vfs::QuotaType::Project).expect("sync v0");
    vfs::quota_off(&sb, vfs::QuotaType::Project).expect("quota_off v0");
    drop(sb); drop(m);

    let (_m2, sb2) = mount(disk);
    sb2.s_op.quota_on(&sb2, vfs::QuotaType::Project, vfs::QFMT_VFS_V0, None).expect("quota_on v0 remount");
    let got = vfs::quota_getquota(&sb2, qid).expect("getquota v0 remount");
    assert_eq!(got.dqb_bhardlimit, want.dqb_bhardlimit);
    assert_eq!(got.dqb_bsoftlimit, want.dqb_bsoftlimit);
    assert_eq!(got.dqb_curspace, want.dqb_curspace);
    assert_eq!(got.dqb_ihardlimit, want.dqb_ihardlimit);
    assert_eq!(got.dqb_isoftlimit, want.dqb_isoftlimit);
    assert_eq!(got.dqb_curinodes, want.dqb_curinodes);
    assert_eq!(got.dqb_btime, want.dqb_btime);
    assert_eq!(got.dqb_itime, want.dqb_itime);
}
