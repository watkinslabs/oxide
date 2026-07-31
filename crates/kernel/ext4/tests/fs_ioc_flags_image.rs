//! B2 (ext4fix §7.3): FS_IOC_GETFLAGS/SETFLAGS backend — the ext4 inode's
//! on-disk `i_flags` (chattr/lsattr) round-trip through `fileattr_get`/`set`,
//! persist across a remount, only touch the user-modifiable bits (the extent
//! layout flag EXTENTS_FL is preserved), and mirror IMMUTABLE into the in-core
//! VFS `i_flags` for enforcement.
//!
//! Image: mini-j.img (journaled — fileattr_set writes through run_journaled).

extern crate alloc;
mod common;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{FileAttr, SuperBlock, VfsError};

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
const EXT4_RO_COMPAT_OFF: usize = EXT4_SUPERBLOCK_OFFSET + 0x64;
const EXT4_PRJ_QUOTA_INUM_OFF: usize = EXT4_SUPERBLOCK_OFFSET + ext4::superblock::SB_OFF_PRJ_QUOTA_INUM;
const HELLO_INO: u32 = 12;
const PRJ_MAGIC: u32 = 0xd9c0_3f14;
const V2_VERSION_V1: u32 = 1;

// FS_*_FL == ext4 on-disk i_flags bits.
const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
const FS_NODUMP_FL:    u32 = 0x0000_0040;
const FS_JOURNAL_DATA_FL: u32 = 0x0000_4000;
const FS_DAX_FL:       u32 = 0x0200_0000;
const FS_PROJINHERIT_FL: u32 = 0x2000_0000;
const EXT4_EXTENTS_FL: u32 = 0x0008_0000; // kernel-internal, must be preserved
const EXT4_FEATURE_RO_COMPAT_PROJECT: u32 = ext4::superblock::RO_COMPAT_PROJECT;
const T_FILEATTR: u64 = 1_720_007_200 * 1_000_000_000 + 125_000_000;
fn t_fileattr() -> vfs::Timespec64 { vfs::Timespec64::from_clock_ns(T_FILEATTR) }

static NOW: AtomicU64 = AtomicU64::new(T_FILEATTR);
fn now_provider() -> u64 { NOW.load(Ordering::Relaxed) }

fn shared_disk_from(image: Vec<u8>) -> Arc<dyn BlockDevice> {
    let cap = (image.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: image, ..Default::default() };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

fn shared_disk() -> Arc<dyn BlockDevice> {
    shared_disk_from(IMAGE.to_vec())
}

fn shared_project_disk() -> Arc<dyn BlockDevice> {
    let mut image = IMAGE.to_vec();
    let mut features = u32::from_le_bytes(
        image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4].try_into().unwrap(),
    );
    features |= EXT4_FEATURE_RO_COMPAT_PROJECT;
    image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4].copy_from_slice(&features.to_le_bytes());
    shared_disk_from(image)
}

fn shared_project_quota_file_disk(quota_ino: u32) -> Arc<dyn BlockDevice> {
    let mut image = IMAGE.to_vec();
    let mut features = u32::from_le_bytes(
        image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4].try_into().unwrap(),
    );
    features |= EXT4_FEATURE_RO_COMPAT_PROJECT;
    image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4].copy_from_slice(&features.to_le_bytes());
    image[EXT4_PRJ_QUOTA_INUM_OFF..EXT4_PRJ_QUOTA_INUM_OFF + 4].copy_from_slice(&quota_ino.to_le_bytes());
    shared_disk_from(image)
}

fn empty_project_quota_file() -> Vec<u8> {
    let mut q = vec![0u8; 2048];
    q[0..4].copy_from_slice(&PRJ_MAGIC.to_le_bytes());
    q[4..8].copy_from_slice(&V2_VERSION_V1.to_le_bytes());
    q[20..24].copy_from_slice(&2u32.to_le_bytes());
    q
}

fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_F1A6, String::from("ext4"));
    (m, sb)
}

#[test]
fn chattr_flags_roundtrip_persist_and_preserve() {
    let disk = shared_disk();
    let (m, sb) = mount(disk.clone());
    let inode = m.state().create_at(b"/chattr.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/chattr.txt").expect("lookup");

    // Fresh regular file: EXTENTS_FL is Linux-visible through FS_IOC_GETFLAGS.
    assert_ne!(m.state().mount.read_inode(ino).unwrap().i_flags & EXT4_EXTENTS_FL, 0,
        "regular file carries EXTENTS_FL");
    let initial_flags = inode.fileattr_get().unwrap().flags;
    assert_ne!(initial_flags & EXT4_EXTENTS_FL, 0, "GETFLAGS reports EXTENTS_FL");
    assert_eq!(initial_flags & (FS_IMMUTABLE_FL | FS_NODUMP_FL), 0, "no chattr flags initially");

    // chattr +i +d (immutable + nodump).
    inode.fileattr_set(&FileAttr { flags: initial_flags | FS_IMMUTABLE_FL | FS_NODUMP_FL, ..Default::default() })
        .expect("fileattr_set");
    assert_eq!(inode.fileattr_get().unwrap().flags & (FS_IMMUTABLE_FL | FS_NODUMP_FL),
        FS_IMMUTABLE_FL | FS_NODUMP_FL, "get reflects the set flags");
    // Kernel-internal EXTENTS_FL preserved (only user-modifiable bits changed).
    assert_ne!(m.state().mount.read_inode(ino).unwrap().i_flags & EXT4_EXTENTS_FL, 0,
        "EXTENTS_FL preserved across SETFLAGS");
    // In-core VFS inode reflects immutable for enforcement.
    assert_ne!(inode.i_flags() & vfs::S_IMMUTABLE, 0, "S_IMMUTABLE mirrored in-core");

    // Persist across remount.
    drop(sb); drop(m);
    let (m2, _sb2) = mount(disk);
    let node = m2.state().lookup_inode_any(b"/chattr.txt").expect("lookup after remount");
    assert_eq!(node.fileattr_get().unwrap().flags & (FS_IMMUTABLE_FL | FS_NODUMP_FL),
        FS_IMMUTABLE_FL | FS_NODUMP_FL, "remount: chattr flags persisted");

    // chattr -i -d clears them, still preserving EXTENTS_FL.
    node.fileattr_set(&FileAttr { flags: EXT4_EXTENTS_FL, ..Default::default() }).expect("clear");
    assert_eq!(node.fileattr_get().unwrap().flags & (FS_IMMUTABLE_FL | FS_NODUMP_FL), 0, "cleared");
    let ino2 = m2.state().mount.lookup_path(b"/chattr.txt").unwrap();
    assert_ne!(m2.state().mount.read_inode(ino2).unwrap().i_flags & EXT4_EXTENTS_FL, 0,
        "EXTENTS_FL still preserved after clear");
}

#[test]
fn setflags_updates_ctime_and_iversion() {
    vfs::inode_times::set_realtime_provider(now_provider);
    NOW.store(T_FILEATTR, Ordering::Relaxed);
    let disk = shared_disk();
    let (m, sb) = mount(disk.clone());
    let inode = m.state().create_at(b"/chattr-time.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/chattr-time.txt").expect("lookup");
    let before_version = vfs::inode::inode_query_iversion(&inode);
    let flags = inode.fileattr_get().unwrap().flags;

    inode.fileattr_set(&FileAttr { flags: flags | FS_NODUMP_FL, ..Default::default() })
        .expect("set nodump");
    assert_eq!(inode.ctime(), Some(t_fileattr()), "in-core ctime stamped by SETFLAGS");
    assert!(vfs::inode::inode_query_iversion(&inode) > before_version,
        "SETFLAGS forces i_version bump like ext4_ioctl_setflags");
    assert_eq!(m.state().mount.read_inode(ino).unwrap().ctime, t_fileattr(),
        "on-disk ctime stamped by SETFLAGS");

    drop(inode); drop(sb); drop(m);
    let (m2, _sb2) = mount(disk);
    let ino2 = m2.state().mount.lookup_path(b"/chattr-time.txt").expect("lookup after remount");
    assert_eq!(m2.state().mount.read_inode(ino2).unwrap().ctime, t_fileattr(),
        "remount: SETFLAGS ctime persisted");
}

#[test]
fn non_project_ext4_rejects_nonzero_project_id() {
    let disk = shared_disk();
    let (m, _sb) = mount(disk);
    let inode = m.state().create_at(b"/projid.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/projid.txt").expect("lookup");

    assert_eq!(inode.fileattr_get().unwrap().fsx_projid, 0);
    assert_eq!(inode.fileattr_set(&FileAttr { fsx_projid: 42, ..Default::default() }),
        Err(VfsError::Eopnotsupp));
    assert_eq!(inode.fileattr_get().unwrap().fsx_projid, 0);
    assert_eq!(m.state().mount.read_inode(ino).unwrap().i_projid, 0);

    let flags = inode.fileattr_get().unwrap().flags;
    assert_eq!(inode.fileattr_set(&FileAttr { flags: flags | FS_NODUMP_FL, fsx_projid: 42, ..Default::default() }),
        Err(VfsError::Eopnotsupp));
    assert_ne!(inode.fileattr_get().unwrap().flags & FS_NODUMP_FL, 0,
        "Linux ext4 applies flags before unsupported project-id rejection");
}

#[test]
fn project_ext4_persists_nonzero_project_id() {
    let disk = shared_project_disk();
    let (m, sb) = mount(disk.clone());
    let inode = m.state().create_at(b"/project.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/project.txt").expect("lookup");

    assert_eq!(inode.fileattr_get().unwrap().fsx_projid, 0);
    let flags = inode.fileattr_get().unwrap().flags;
    inode.fileattr_set(&FileAttr { flags, fsx_projid: 77, ..Default::default() })
        .expect("set project id");
    assert_eq!(inode.fileattr_get().unwrap().fsx_projid, 77);
    assert_eq!(m.state().mount.read_inode(ino).unwrap().i_projid, 77);

    drop(sb); drop(m);
    let (m2, _sb2) = mount(disk);
    let node = m2.state().lookup_inode_any(b"/project.txt").expect("lookup after remount");
    assert_eq!(node.fileattr_get().unwrap().fsx_projid, 77);
}

#[test]
fn project_id_change_bumps_iversion_after_setflags() {
    let disk = shared_project_disk();
    let (m, _sb) = mount(disk);
    let inode = m.state().create_at(b"/project-version.txt", 0o644).expect("create");
    let flags = inode.fileattr_get().unwrap().flags;
    let before = vfs::inode::inode_query_iversion(&inode);

    inode.fileattr_set(&FileAttr { flags, fsx_projid: 88, ..Default::default() })
        .expect("set project id");

    assert_eq!(vfs::inode::inode_query_iversion(&inode), before + 2,
        "Linux ext4_fileattr_set runs ext4_ioctl_setflags and ext4_ioctl_setproject, both force i_version");
}

#[test]
fn project_id_change_transfers_project_quota_usage() {
    common::boot_hosted_pmm();
    let disk = shared_project_quota_file_disk(HELLO_INO);
    let (m, sb) = mount(disk);
    m.state().mount.write_at(HELLO_INO, 0, &empty_project_quota_file()).expect("seed quota file");
    sb.s_op.quota_on(&sb, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, None).expect("quota_on");

    let inode = m.state().create_at(b"/charged-project.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/charged-project.txt").expect("lookup");
    m.state().mount.write_at(ino, 0, &[0x5a; 2048]).expect("write file");
    let usage = m.state().mount.read_inode(ino).expect("read raw").i_blocks as u64 * 512;
    assert_ne!(usage, 0);

    let before = vfs::quota_getquota(&sb, vfs::Kqid::project(0)).expect("old project quota");
    assert_eq!(before.dqb_curspace, usage);
    assert_eq!(before.dqb_curinodes, 1);

    let flags = inode.fileattr_get().unwrap().flags;
    inode.fileattr_set(&FileAttr { flags, fsx_projid: 77, ..Default::default() })
        .expect("set project id");

    let old = vfs::quota_getquota(&sb, vfs::Kqid::project(0)).expect("old after transfer");
    let new = vfs::quota_getquota(&sb, vfs::Kqid::project(77)).expect("new after transfer");
    assert_eq!(old.dqb_curspace, 0);
    assert_eq!(old.dqb_curinodes, 0);
    assert_eq!(new.dqb_curspace, usage);
    assert_eq!(new.dqb_curinodes, 1);
}

#[test]
fn project_id_change_after_iget_uses_cached_disk_project_id_for_quota_transfer() {
    common::boot_hosted_pmm();
    let disk = shared_project_quota_file_disk(HELLO_INO);
    let (m, sb) = mount(disk);
    m.state().mount.write_at(HELLO_INO, 0, &empty_project_quota_file()).expect("seed quota file");
    sb.s_op.quota_on(&sb, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, None).expect("quota_on");

    let inode = m.state().create_at(b"/cached-project.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/cached-project.txt").expect("lookup");
    let flags = inode.fileattr_get().unwrap().flags;
    inode.fileattr_set(&FileAttr { flags, fsx_projid: 11, ..Default::default() })
        .expect("set initial project id");
    m.state().mount.write_at(ino, 0, &[0x5a; 2048]).expect("write file");
    let usage = m.state().mount.read_inode(ino).expect("read raw").i_blocks as u64 * 512;
    assert_ne!(usage, 0);
    assert_eq!(vfs::quota_getquota(&sb, vfs::Kqid::project(11)).expect("project 11").dqb_curspace, usage);

    let vfs_ino = inode.ino();
    drop(inode);
    sb.iforget(vfs_ino);
    let inode = m.state().lookup_inode_any(b"/cached-project.txt").expect("re-iget cached inode");
    assert_eq!(inode.fileattr_get().unwrap().fsx_projid, 11);

    let flags = inode.fileattr_get().unwrap().flags;
    inode.fileattr_set(&FileAttr { flags, fsx_projid: 77, ..Default::default() })
        .expect("transfer from reloaded project id");

    let old = vfs::quota_getquota(&sb, vfs::Kqid::project(11)).expect("old after transfer");
    let new = vfs::quota_getquota(&sb, vfs::Kqid::project(77)).expect("new after transfer");
    assert_eq!(old.dqb_curspace, 0);
    assert_eq!(old.dqb_curinodes, 0);
    assert_eq!(new.dqb_curspace, usage);
    assert_eq!(new.dqb_curinodes, 1);
}

#[test]
fn project_id_change_edquot_leaves_project_and_quota_unchanged() {
    common::boot_hosted_pmm();
    let disk = shared_project_quota_file_disk(HELLO_INO);
    let (m, sb) = mount(disk);
    m.state().mount.write_at(HELLO_INO, 0, &empty_project_quota_file()).expect("seed quota file");
    sb.s_op.quota_on(&sb, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, None).expect("quota_on");

    let inode = m.state().create_at(b"/project-edquot.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/project-edquot.txt").expect("lookup");
    m.state().mount.write_at(ino, 0, &[0x5a; 2048]).expect("write file");
    let usage = m.state().mount.read_inode(ino).expect("read raw").i_blocks as u64 * 512;
    assert_ne!(usage, 0);

    let before_old = vfs::quota_getquota(&sb, vfs::Kqid::project(0)).expect("old project before");
    let before_new = vfs::quota_getquota(&sb, vfs::Kqid::project(77)).expect("new project before");
    vfs::quota_setquota(&sb, vfs::Kqid::project(77), vfs::MemDqblk {
        dqb_bhardlimit: 1,
        dqb_curspace: before_new.dqb_curspace,
        dqb_curinodes: before_new.dqb_curinodes,
        ..vfs::MemDqblk::new()
    }).expect("limit destination project");

    let flags = inode.fileattr_get().unwrap().flags;
    assert_eq!(
        inode.fileattr_set(&FileAttr { flags, fsx_projid: 77, ..Default::default() }),
        Err(VfsError::Edquot),
    );

    assert_eq!(inode.fileattr_get().unwrap().fsx_projid, 0);
    assert_eq!(m.state().mount.read_inode(ino).unwrap().i_projid, 0);
    assert_eq!(vfs::quota_getquota(&sb, vfs::Kqid::project(0)).expect("old after").dqb_curspace, before_old.dqb_curspace);
    assert_eq!(vfs::quota_getquota(&sb, vfs::Kqid::project(0)).expect("old after").dqb_curinodes, before_old.dqb_curinodes);
    assert_eq!(vfs::quota_getquota(&sb, vfs::Kqid::project(77)).expect("new after").dqb_curspace, before_new.dqb_curspace);
    assert_eq!(vfs::quota_getquota(&sb, vfs::Kqid::project(77)).expect("new after").dqb_curinodes, before_new.dqb_curinodes);
}

#[test]
fn hidden_project_quota_file_rejects_fileattr_change() {
    let disk = shared_project_quota_file_disk(HELLO_INO);
    let (m, _sb) = mount(disk);
    let ino = m.state().mount.lookup_path(b"/hello.txt").expect("lookup hello");
    assert_eq!(ino, HELLO_INO, "fixture inode changed");
    assert_eq!(m.state().mount.sb.prj_quota_inum, HELLO_INO);
    let inode = m.state().lookup_inode_any(b"/hello.txt").expect("inode");
    let before = inode.fileattr_get().unwrap();

    assert_eq!(inode.fileattr_set(&FileAttr { flags: before.flags | FS_NODUMP_FL, fsx_projid: 55, ..Default::default() }),
        Err(VfsError::Eperm));

    let after = inode.fileattr_get().unwrap();
    assert_eq!(after.flags & FS_NODUMP_FL, before.flags & FS_NODUMP_FL);
    assert_eq!(after.fsx_projid, before.fsx_projid);
    assert_eq!(m.state().mount.read_inode(ino).unwrap().i_projid, before.fsx_projid);
}

#[test]
fn ext4_rejects_extent_layout_toggle_without_corruption() {
    let disk = shared_disk();
    let (m, _sb) = mount(disk);
    let inode = m.state().create_at(b"/extent-toggle.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/extent-toggle.txt").expect("lookup");
    let flags = inode.fileattr_get().unwrap().flags;

    assert_ne!(flags & EXT4_EXTENTS_FL, 0, "created regular file uses extents");
    assert_eq!(inode.fileattr_set(&FileAttr { flags: flags & !EXT4_EXTENTS_FL, ..Default::default() }),
        Err(VfsError::Eopnotsupp));
    assert_ne!(m.state().mount.read_inode(ino).unwrap().i_flags & EXT4_EXTENTS_FL, 0);
}

#[test]
fn ext4_rejects_unsupported_dax_flag_without_corruption() {
    let disk = shared_disk();
    let (m, _sb) = mount(disk);
    let inode = m.state().create_at(b"/dax.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/dax.txt").expect("lookup");
    let flags = inode.fileattr_get().unwrap().flags;

    assert_eq!(inode.fileattr_set(&FileAttr { flags: flags | FS_DAX_FL, ..Default::default() }),
        Err(VfsError::Eopnotsupp));
    assert_eq!(m.state().mount.read_inode(ino).unwrap().i_flags & FS_DAX_FL, 0);
    assert_eq!(inode.fileattr_get().unwrap().flags & FS_DAX_FL, 0);
}

#[test]
fn ext4_rejects_journal_data_flag_toggle_without_noop_success() {
    let disk = shared_disk();
    let (m, _sb) = mount(disk);
    let inode = m.state().create_at(b"/journal-data.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/journal-data.txt").expect("lookup");
    let flags = inode.fileattr_get().unwrap().flags;

    assert_eq!(flags & FS_JOURNAL_DATA_FL, 0);
    assert_eq!(inode.fileattr_set(&FileAttr { flags: flags | FS_JOURNAL_DATA_FL, ..Default::default() }),
        Err(VfsError::Eopnotsupp));
    assert_eq!(m.state().mount.read_inode(ino).unwrap().i_flags & FS_JOURNAL_DATA_FL, 0);
    assert_eq!(inode.fileattr_get().unwrap().flags & FS_JOURNAL_DATA_FL, 0);
}

#[test]
fn immutable_project_ext4_rejects_project_id_change() {
    let disk = shared_project_disk();
    let (m, _sb) = mount(disk);
    let inode = m.state().create_at(b"/immutable-project.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/immutable-project.txt").expect("lookup");

    let flags = inode.fileattr_get().unwrap().flags;
    inode.fileattr_set(&FileAttr { flags: flags | FS_IMMUTABLE_FL, fsx_projid: 7, ..Default::default() })
        .expect("set immutable project id");
    assert_eq!(inode.fileattr_set(&FileAttr { flags: flags | FS_IMMUTABLE_FL, fsx_projid: 8, ..Default::default() }),
        Err(VfsError::Eperm));
    assert_eq!(m.state().mount.read_inode(ino).unwrap().i_projid, 7);
    assert_eq!(inode.fileattr_get().unwrap().fsx_projid, 7);
}

#[test]
fn immutable_ext4_rejects_other_flag_change() {
    let disk = shared_disk();
    let (m, _sb) = mount(disk);
    let inode = m.state().create_at(b"/immutable-flags.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/immutable-flags.txt").expect("lookup");

    let flags = inode.fileattr_get().unwrap().flags;
    inode.fileattr_set(&FileAttr { flags: flags | FS_IMMUTABLE_FL, ..Default::default() })
        .expect("set immutable");
    assert_eq!(inode.fileattr_set(&FileAttr { flags: flags | FS_IMMUTABLE_FL | FS_NODUMP_FL, ..Default::default() }),
        Err(VfsError::Eperm));
    assert_eq!(m.state().mount.read_inode(ino).unwrap().i_flags & FS_NODUMP_FL, 0);
    assert_eq!(inode.fileattr_get().unwrap().flags & FS_NODUMP_FL, 0);
}

#[test]
fn projinherit_is_directory_only() {
    let disk = shared_disk();
    let (m, _sb) = mount(disk);
    let file = m.state().create_at(b"/not-dir.txt", 0o644).expect("create file");
    assert_eq!(file.fileattr_set(&FileAttr { flags: FS_PROJINHERIT_FL, ..Default::default() }),
        Err(VfsError::Eopnotsupp));
    assert_eq!(file.fileattr_get().unwrap().flags & FS_PROJINHERIT_FL, 0);

    m.state().mkdir_at(b"/dir", 0o755).expect("mkdir");
    let dir = m.state().lookup_inode_any(b"/dir").expect("lookup dir");
    let flags = dir.fileattr_get().unwrap().flags;
    dir.fileattr_set(&FileAttr { flags: flags | FS_PROJINHERIT_FL, ..Default::default() })
        .expect("set dir projinherit");
    assert_ne!(dir.fileattr_get().unwrap().flags & FS_PROJINHERIT_FL, 0);
}

#[test]
fn project_inherit_stamps_new_children() {
    let disk = shared_project_disk();
    let (m, _sb) = mount(disk);
    m.state().mkdir_at(b"/project-dir", 0o755).expect("mkdir");
    let dir = m.state().lookup_inode_any(b"/project-dir").expect("lookup dir");
    let flags = dir.fileattr_get().unwrap().flags;
    dir.fileattr_set(&FileAttr { flags: flags | FS_PROJINHERIT_FL, fsx_projid: 123, ..Default::default() })
        .expect("set projinherit");

    let file = m.state().create_at(b"/project-dir/file", 0o644).expect("create file");
    assert_eq!(file.fileattr_get().unwrap().fsx_projid, 123);

    m.state().mkdir_at(b"/project-dir/subdir", 0o755).expect("mkdir child");
    let subdir = m.state().lookup_inode_any(b"/project-dir/subdir").expect("lookup child dir");
    assert_eq!(subdir.fileattr_get().unwrap().fsx_projid, 123);
    assert_ne!(subdir.fileattr_get().unwrap().flags & FS_PROJINHERIT_FL, 0);

    m.state().symlink_at(b"file", b"/project-dir/link").expect("symlink");
    let link_ino = m.state().mount.lookup_path(b"/project-dir/link").expect("lookup link");
    assert_eq!(m.state().mount.read_inode(link_ino).unwrap().i_projid, 123);
}

#[test]
fn project_inherit_rejects_cross_project_link_and_rename() {
    let disk = shared_project_disk();
    let (m, _sb) = mount(disk);
    m.state().mkdir_at(b"/p1", 0o755).expect("mkdir p1");
    m.state().mkdir_at(b"/p2", 0o755).expect("mkdir p2");
    for (path, projid) in [(b"/p1" as &[u8], 10), (b"/p2" as &[u8], 20)] {
        let dir = m.state().lookup_inode_any(path).expect("lookup dir");
        let flags = dir.fileattr_get().unwrap().flags;
        dir.fileattr_set(&FileAttr { flags: flags | FS_PROJINHERIT_FL, fsx_projid: projid, ..Default::default() })
            .expect("set project dir");
    }
    m.state().create_at(b"/p1/file", 0o644).expect("create file");

    assert_eq!(m.state().link_at(b"/p1/file", b"/p2/hardlink"), Err(VfsError::Exdev));
    assert!(m.state().mount.lookup_path(b"/p2/hardlink").is_err());

    assert_eq!(m.state().rename_at(b"/p1/file", b"/p2/file"), Err(VfsError::Exdev));
    assert!(m.state().mount.lookup_path(b"/p1/file").is_ok());
    assert!(m.state().mount.lookup_path(b"/p2/file").is_err());
}
