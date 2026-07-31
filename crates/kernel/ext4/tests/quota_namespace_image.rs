extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::inode::FS_PROJINHERIT_FL;
use vfs::{CreateCtx, FileAttr, FileType, Kqid, MemDqblk, SuperBlock, VfsError};

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

fn empty_project_quota_file() -> Vec<u8> {
    let mut q = vec![0u8; 2048];
    q[0..4].copy_from_slice(&PRJ_MAGIC.to_le_bytes());
    q[4..8].copy_from_slice(&V2_VERSION_V1.to_le_bytes());
    q[20..24].copy_from_slice(&2u32.to_le_bytes());
    q
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

fn mount_result(disk: Arc<dyn BlockDevice>) -> vfs::KResult<(Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>)> {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb_result(fs, root, 0xE471_F1A6, String::from("ext4"))?;
    Ok((m, sb))
}

fn set_project_dir(m: &Arc<ext4::rootfs::Ext4Mount>, path: &[u8], projid: u32) {
    m.state().mkdir_at(path, 0o755).expect("mkdir project dir");
    let dir = m.state().lookup_inode_any(path).expect("lookup project dir");
    let flags = dir.fileattr_get().expect("project dir attrs").flags;
    dir.fileattr_set(&FileAttr { flags: flags | FS_PROJINHERIT_FL, fsx_projid: projid, ..Default::default() })
        .expect("set project inherit");
}

fn curinodes(sb: &SuperBlock, qid: Kqid) -> u64 {
    vfs::quota_getquota(sb, qid).expect("quota record").dqb_curinodes
}

fn raw_space(m: &ext4::rootfs::Ext4Mount, ino: u32) -> u64 {
    m.state().mount.read_inode(ino).expect("raw inode").i_blocks as u64 * 512
}

#[test]
fn project_inherit_namespace_ops_account_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(123);
    set_project_dir(&m, b"/proj", 123);
    assert_eq!(curinodes(&sb, qid), 1, "project dir transfer charges project 123");

    let file = m.state().create_at(b"/proj/file", 0o644).expect("create project file");
    assert_eq!(file.fileattr_get().unwrap().fsx_projid, 123);
    assert_eq!(curinodes(&sb, qid), 2, "regular create charges one inode");

    m.state().mkdir_at(b"/proj/subdir", 0o755).expect("mkdir child");
    assert_eq!(curinodes(&sb, qid), 3, "mkdir charges one inode");

    m.state().symlink_at(b"file-hard", b"/proj/link").expect("symlink child");
    assert_eq!(curinodes(&sb, qid), 4, "symlink charges one inode");

    m.state().mknod_at(b"/proj/fifo", (vfs::S_IFIFO as u16) | 0o600, 0).expect("fifo child");
    assert_eq!(m.state().lookup_inode_any(b"/proj/fifo").unwrap().file_type(), FileType::Fifo);
    assert_eq!(curinodes(&sb, qid), 5, "mknod charges one inode");

    let tmp = m.state().create_anonymous_at(b"/proj", 0o600).expect("anonymous child");
    assert_eq!(curinodes(&sb, qid), 6, "tmpfile charges one inode");
    m.state().free_orphan_inode(tmp.ino() as u32).expect("free tmpfile orphan");
    assert_eq!(curinodes(&sb, qid), 5, "freeing orphan releases tmpfile charge");

    m.state().link_at(b"/proj/file", b"/proj/file-hard").expect("hardlink");
    assert_eq!(curinodes(&sb, qid), 5, "hardlink does not double-charge inode");

    m.state().rename_at(b"/proj/file", b"/proj/file-renamed").expect("rename");
    assert_eq!(curinodes(&sb, qid), 5, "plain rename preserves inode usage");

    m.state().exchange_at(b"/proj/file-renamed", b"/proj/fifo").expect("exchange");
    assert_eq!(curinodes(&sb, qid), 5, "exchange preserves inode usage");

    m.state().create_at(b"/proj/wo-src", 0o644).expect("create whiteout source");
    assert_eq!(curinodes(&sb, qid), 6, "whiteout source create charges one inode");
    m.state().whiteout_at(b"/proj/wo-src", b"/proj/whiteout-dst").expect("whiteout rename");
    assert_eq!(m.state().lookup_inode_any(b"/proj/wo-src").unwrap().file_type(), FileType::CharDev);
    assert_eq!(curinodes(&sb, qid), 7, "whiteout charges the planted char device");

    m.state().unlink_at(b"/proj/whiteout-dst").expect("unlink moved whiteout source");
    assert_eq!(curinodes(&sb, qid), 6, "final unlink of an UNHELD inode evicts it and releases the charge");
    m.state().unlink_at(b"/proj/file-hard").expect("unlink non-final regular name");
    assert_eq!(curinodes(&sb, qid), 6, "non-final hardlink unlink does not release regular inode");

    // `/proj/fifo` names the regular file after the EXCHANGE above, and `file`
    // is still a counted holder of it. `__ext4_unlink` (`fs/ext4/namei.c`)
    // deletes the entry, `drop_nlink`s and `ext4_orphan_add`s — it calls no
    // dquot function at all. The charge only comes back from
    // `dquot_free_inode` inside `ext4_free_inode` (`fs/ext4/ialloc.c:275`),
    // which `ext4_evict_inode` reaches on the LAST reference. That is the POSIX
    // unlink-while-open guarantee expressed in quota terms.
    m.state().unlink_at(b"/proj/fifo").expect("unlink final name of a still-held inode");
    assert_eq!(m.state().lookup_path(b"/proj/fifo"), None, "the name goes immediately");
    assert_eq!(curinodes(&sb, qid), 6, "unlink of a HELD inode keeps its charge until eviction");
    vfs::file::iput(file);
    assert_eq!(curinodes(&sb, qid), 5, "the last iput evicts the orphan and releases the charge");

    m.state().rmdir_at(b"/proj/subdir").expect("rmdir child");
    assert_eq!(curinodes(&sb, qid), 4, "cleanup leaves project dir plus retained symlink, fifo, and whiteout charged");
}

#[test]
fn project_inherit_vfs_inode_ops_account_project_quota() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(123);
    set_project_dir(&m, b"/iop-proj", 123);
    let dir = m.state().lookup_inode_any(b"/iop-proj").expect("lookup project dir");
    assert_eq!(curinodes(&sb, qid), 1, "project dir transfer charges project 123");

    let file = dir.create_child("file", 0o644, &CreateCtx::root()).expect("i_op create");
    assert_eq!(file.fileattr_get().unwrap().fsx_projid, 123);
    assert_eq!(curinodes(&sb, qid), 2, "i_op create charges one inode");

    let subdir = dir.mkdir("subdir", 0o755, &CreateCtx::root()).expect("i_op mkdir");
    assert_eq!(subdir.fileattr_get().unwrap().fsx_projid, 123);
    assert_eq!(curinodes(&sb, qid), 3, "i_op mkdir charges one inode");

    dir.symlink_child("link", b"file-hard", &CreateCtx::root()).expect("i_op symlink");
    assert_eq!(dir.lookup("link").unwrap().fileattr_get().unwrap().fsx_projid, 123);
    assert_eq!(curinodes(&sb, qid), 4, "i_op symlink charges one inode");

    dir.mknod_child("fifo", (vfs::S_IFIFO as u16) | 0o600, 0, &CreateCtx::root()).expect("i_op mknod");
    assert_eq!(dir.lookup("fifo").unwrap().file_type(), FileType::Fifo);
    assert_eq!(dir.lookup("fifo").unwrap().fileattr_get().unwrap().fsx_projid, 123);
    assert_eq!(curinodes(&sb, qid), 5, "i_op mknod charges one inode");

    let tmp = dir.tmpfile(0o600, &CreateCtx::root()).expect("i_op tmpfile");
    assert_eq!(tmp.fileattr_get().unwrap().fsx_projid, 123);
    assert_eq!(curinodes(&sb, qid), 6, "i_op tmpfile charges one inode");
    m.state().free_orphan_inode(tmp.ino() as u32).expect("free i_op tmpfile orphan");
    assert_eq!(curinodes(&sb, qid), 5, "freeing i_op tmpfile orphan releases charge");

    dir.link_child(&file, "file-hard", &CreateCtx::root()).expect("i_op hardlink");
    assert_eq!(curinodes(&sb, qid), 5, "i_op hardlink does not double-charge inode");
    dir.unlink_child("file").expect("i_op unlink non-final name");
    assert_eq!(curinodes(&sb, qid), 5, "i_op non-final unlink does not release inode");
    // `file` is still a counted holder, so the final unlink only orphans the
    // inode: `__ext4_unlink` (`fs/ext4/namei.c`) removes the dirent,
    // `drop_nlink`s and `ext4_orphan_add`s, with no dquot call anywhere in it.
    dir.unlink_child("file-hard").expect("i_op unlink final name");
    assert!(dir.lookup("file-hard").is_err(), "the name goes immediately");
    assert_eq!(file.nlink(), 0, "final unlink zeroes the cached link count");
    assert_eq!(curinodes(&sb, qid), 5, "the charge survives an unlink that still has an i_count holder");
    // `iput` → `ext4_evict_inode` → `ext4_free_inode` → `dquot_free_inode`
    // (`fs/ext4/ialloc.c:275`) is what actually gives the charge back.
    vfs::file::iput(file);
    assert_eq!(curinodes(&sb, qid), 4, "eviction on the last iput releases the inode charge");
}

#[test]
fn project_inherit_slow_symlink_accounts_and_limits_project_space() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(123);
    set_project_dir(&m, b"/slow-link", 123);
    let dir = m.state().lookup_inode_any(b"/slow-link").expect("lookup project dir");
    let base = vfs::quota_getquota(&sb, qid).expect("quota after project dir");
    let target = vec![b'x'; 96];

    m.state().symlink_at(&target, b"/slow-link/direct").expect("slow symlink");
    let direct = dir.lookup("direct").expect("lookup direct slow symlink");
    assert_eq!(direct.fileattr_get().unwrap().fsx_projid, 123);
    let direct_space = raw_space(&m, direct.ino() as u32);
    assert_ne!(direct_space, 0, "slow symlink must allocate an external data block");
    let after_direct = vfs::quota_getquota(&sb, qid).expect("quota after direct slow symlink");
    assert_eq!(after_direct.dqb_curinodes, base.dqb_curinodes + 1);
    assert_eq!(after_direct.dqb_curspace, base.dqb_curspace + direct_space);

    dir.symlink_child("iop", &target, &CreateCtx::root()).expect("i_op slow symlink");
    let iop = dir.lookup("iop").expect("lookup i_op slow symlink");
    assert_eq!(iop.fileattr_get().unwrap().fsx_projid, 123);
    let iop_space = raw_space(&m, iop.ino() as u32);
    assert_ne!(iop_space, 0, "i_op slow symlink must allocate an external data block");
    let after_iop = vfs::quota_getquota(&sb, qid).expect("quota after i_op slow symlink");
    assert_eq!(after_iop.dqb_curinodes, base.dqb_curinodes + 2);
    assert_eq!(after_iop.dqb_curspace, base.dqb_curspace + direct_space + iop_space);

    set_project_dir(&m, b"/slow-limit", 124);
    let limit_qid = Kqid::project(124);
    let before_limit = vfs::quota_getquota(&sb, limit_qid).expect("quota before limit");
    vfs::quota_setquota(&sb, limit_qid, MemDqblk {
        dqb_bhardlimit: before_limit.dqb_curspace,
        dqb_ihardlimit: before_limit.dqb_curinodes + 4,
        dqb_curspace: before_limit.dqb_curspace,
        dqb_curinodes: before_limit.dqb_curinodes,
        ..MemDqblk::new()
    }).expect("set block hardlimit at current space");
    vfs::quota_enable_limits(&sb, vfs::QuotaType::Project).expect("enable project limits");
    assert_eq!(m.state().symlink_at(&target, b"/slow-limit/blocked"), Err(VfsError::Edquot));
    let limit_dir = m.state().lookup_inode_any(b"/slow-limit").expect("lookup limit dir");
    assert!(limit_dir.lookup("blocked").is_err());
    let after_limit = vfs::quota_getquota(&sb, limit_qid).expect("quota after blocked slow symlink");
    assert_eq!(after_limit.dqb_curinodes, before_limit.dqb_curinodes);
    assert_eq!(after_limit.dqb_curspace, before_limit.dqb_curspace);
}

#[test]
fn project_inherit_create_family_edquot_leaves_namespace_and_quota_unchanged() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(123);
    set_project_dir(&m, b"/limit", 123);
    let before = vfs::quota_getquota(&sb, qid).expect("quota before limit");
    assert_eq!(before.dqb_curinodes, 1);
    vfs::quota_setquota(&sb, qid, MemDqblk {
        dqb_bhardlimit: 100,
        dqb_ihardlimit: before.dqb_curinodes,
        dqb_curspace: before.dqb_curspace,
        dqb_curinodes: before.dqb_curinodes,
        ..MemDqblk::new()
    }).expect("set inode hardlimit at current usage");
    vfs::quota_enable_limits(&sb, vfs::QuotaType::Project).expect("enable project limits");

    assert!(m.state().create_at(b"/limit/file", 0o644).is_none(), "create fails with EDQUOT");
    assert_eq!(m.state().mkdir_at(b"/limit/dir", 0o755), Err(VfsError::Edquot));
    assert_eq!(m.state().symlink_at(b"file", b"/limit/link"), Err(VfsError::Edquot));
    assert_eq!(m.state().mknod_at(b"/limit/fifo", (vfs::S_IFIFO as u16) | 0o600, 0), Err(VfsError::Edquot));
    assert!(m.state().create_anonymous_at(b"/limit", 0o600).is_none(), "tmpfile fails with EDQUOT");

    for path in [b"/limit/file" as &[u8], b"/limit/dir", b"/limit/link", b"/limit/fifo"] {
        assert!(m.state().lookup_inode_any(path).is_none(), "failed create must not leave namespace entry");
    }
    let after = vfs::quota_getquota(&sb, qid).expect("quota after failures");
    assert_eq!(after.dqb_curinodes, before.dqb_curinodes);
    assert_eq!(after.dqb_curspace, before.dqb_curspace);
}

#[test]
fn project_inherit_vfs_inode_create_family_edquot_leaves_namespace_and_quota_unchanged() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(123);
    set_project_dir(&m, b"/iop-limit", 123);
    let dir = m.state().lookup_inode_any(b"/iop-limit").expect("lookup project dir");
    let before = vfs::quota_getquota(&sb, qid).expect("quota before limit");
    assert_eq!(before.dqb_curinodes, 1);
    vfs::quota_setquota(&sb, qid, MemDqblk {
        dqb_bhardlimit: 100,
        dqb_ihardlimit: before.dqb_curinodes,
        dqb_curspace: before.dqb_curspace,
        dqb_curinodes: before.dqb_curinodes,
        ..MemDqblk::new()
    }).expect("set inode hardlimit at current usage");
    vfs::quota_enable_limits(&sb, vfs::QuotaType::Project).expect("enable project limits");

    match dir.create_child("file", 0o644, &CreateCtx::root()) {
        Err(e) => assert_eq!(e, VfsError::Edquot),
        Ok(_) => panic!("i_op create unexpectedly succeeded"),
    }
    match dir.mkdir("subdir", 0o755, &CreateCtx::root()) {
        Err(e) => assert_eq!(e, VfsError::Edquot),
        Ok(_) => panic!("i_op mkdir unexpectedly succeeded"),
    }
    assert_eq!(dir.symlink_child("link", b"file", &CreateCtx::root()), Err(VfsError::Edquot));
    assert_eq!(dir.mknod_child("fifo", (vfs::S_IFIFO as u16) | 0o600, 0, &CreateCtx::root()), Err(VfsError::Edquot));
    match dir.tmpfile(0o600, &CreateCtx::root()) {
        Err(e) => assert_eq!(e, VfsError::Edquot),
        Ok(_) => panic!("i_op tmpfile unexpectedly succeeded"),
    }

    for name in ["file", "subdir", "link", "fifo"] {
        assert!(dir.lookup(name).is_err(), "failed i_op create must not leave namespace entry");
    }
    let after = vfs::quota_getquota(&sb, qid).expect("quota after failures");
    assert_eq!(after.dqb_curinodes, before.dqb_curinodes);
    assert_eq!(after.dqb_curspace, before.dqb_curspace);
}

#[test]
fn project_inherit_write_append_and_xattr_account_project_space() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(123);
    set_project_dir(&m, b"/space", 123);
    let base = vfs::quota_getquota(&sb, qid).expect("quota after project dir");

    let file = m.state().create_at(b"/space/file", 0o644).expect("create project file");
    let ino = file.ino() as u32;
    let free_blocks_before_file_data = m.state().mount.state_free_blocks();
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after create").dqb_curspace, base.dqb_curspace);

    let bs = m.state().mount.sb.block_size as usize;
    m.state().mount.write_at(ino, 0, &vec![0x41; bs]).expect("write project file");
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after write").dqb_curspace,
        base.dqb_curspace + raw_space(&m, ino));

    m.state().mount.append_block(ino, &vec![0x42; bs]).expect("append project file");
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after append").dqb_curspace,
        base.dqb_curspace + raw_space(&m, ino));

    file.setxattr("user.project-space", vec![0x43; 200], false, false).expect("external xattr");
    assert_eq!(vfs::quota_getquota(&sb, qid).expect("quota after xattr").dqb_curspace,
        base.dqb_curspace + raw_space(&m, ino));

    let charged = raw_space(&m, ino);
    m.state().unlink_at(b"/space/file").expect("unlink project file");

    // The name is gone, but `file` still holds the inode. `__ext4_unlink`
    // (`fs/ext4/namei.c`) frees NOTHING — no truncate, no `ext4_free_inode`, no
    // dquot call — so the data blocks and the space charge both stay live for
    // as long as a reference exists. This is the invariant that makes an
    // unlinked-but-open file readable and writable through its fd.
    assert_eq!(m.state().lookup_path(b"/space/file"), None, "the name goes immediately");
    let held = vfs::quota_getquota(&sb, qid).expect("quota after unlink while held");
    assert_eq!(held.dqb_curspace, base.dqb_curspace + charged, "unlink-while-held keeps the space charged");
    assert_eq!(held.dqb_curinodes, base.dqb_curinodes + 1, "unlink-while-held keeps the inode charged");
    assert_ne!(m.state().mount.state_free_blocks(), free_blocks_before_file_data,
        "the data and xattr blocks stay allocated until eviction");

    // `ext4_evict_inode` → `ext4_free_inode` → `dquot_free_inode`
    // (`fs/ext4/ialloc.c:275`) is the release point.
    vfs::file::iput(file);
    let after = vfs::quota_getquota(&sb, qid).expect("quota after eviction");
    assert_eq!(after.dqb_curspace, base.dqb_curspace);
    assert_eq!(after.dqb_curinodes, base.dqb_curinodes);
    assert_eq!(m.state().mount.state_free_blocks(), free_blocks_before_file_data);
}

#[test]
fn project_inherit_rename_overwrite_releases_replaced_project_usage() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_result(seeded_quota_disk()).expect("rw mount with hidden quota");
    let qid = Kqid::project(123);
    set_project_dir(&m, b"/replace", 123);
    let base = vfs::quota_getquota(&sb, qid).expect("quota after project dir");

    let src = m.state().create_at(b"/replace/src", 0o644).expect("create source");
    let dst = m.state().create_at(b"/replace/dst", 0o644).expect("create dest");
    let src_ino = src.ino() as u32;
    let dst_ino = dst.ino() as u32;
    let bs = m.state().mount.sb.block_size as usize;
    m.state().mount.write_at(src_ino, 0, &vec![0x51; bs]).expect("write source");
    m.state().mount.write_at(dst_ino, 0, &vec![0x52; bs * 2]).expect("write dest");
    drop(src);
    drop(dst);

    let src_space = raw_space(&m, src_ino);
    let dst_space = raw_space(&m, dst_ino);
    assert_ne!(src_space, 0);
    assert_ne!(dst_space, 0);
    let before = vfs::quota_getquota(&sb, qid).expect("quota before rename overwrite");
    assert_eq!(before.dqb_curinodes, base.dqb_curinodes + 2);
    assert_eq!(before.dqb_curspace, base.dqb_curspace + src_space + dst_space);

    m.state().rename_at(b"/replace/src", b"/replace/dst").expect("rename overwrite");

    assert_eq!(m.state().lookup_path(b"/replace/src"), None);
    assert_eq!(m.state().lookup_path(b"/replace/dst"), Some(src_ino));
    let after = vfs::quota_getquota(&sb, qid).expect("quota after rename overwrite");
    assert_eq!(after.dqb_curinodes, base.dqb_curinodes + 1);
    assert_eq!(after.dqb_curspace, base.dqb_curspace + src_space);
}
