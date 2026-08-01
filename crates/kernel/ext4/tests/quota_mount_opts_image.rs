//! ext4 quota MOUNT OPTIONS end to end: what `-o usrquota/prjquota/
//! usrjquota=/jqfmt=/noquota` does to a real mounted filesystem.
//!
//! The option parser is unit-tested in the crate; this drives the whole mount
//! path, so it proves the options actually reach `sb.s_dquot` instead of being
//! parsed and dropped.

extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::SuperBlock;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const SECTOR: u32 = 512;
const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
const EXT4_RO_COMPAT_OFF: usize = EXT4_SUPERBLOCK_OFFSET + 0x64;
const EXT4_PRJ_QUOTA_INUM_OFF: usize = EXT4_SUPERBLOCK_OFFSET + ext4::superblock::SB_OFF_PRJ_QUOTA_INUM;
const EXT4_FEATURE_RO_COMPAT_QUOTA: u32 = ext4::superblock::RO_COMPAT_QUOTA;
const EXT4_FEATURE_RO_COMPAT_PROJECT: u32 = ext4::superblock::RO_COMPAT_PROJECT;
const HELLO_INO: u32 = 12;
const PRJ_MAGIC: u32 = 0xd9c0_3f14;
const USR_MAGIC: u32 = 0xd9c0_1f11;
const V2_VERSION_V1: u32 = 1;
const QUOTA_FILE_BYTES: usize = 2048;
const QUOTA_ROOT_BLOCK: u32 = 2;
const QF_MAGIC_OFF: usize = 0;
const QF_VERSION_OFF: usize = 4;
const QF_FREE_BLK_OFF: usize = 20;
const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
const USR_QUOTA_FILE: &str = "aquota.user";
const DEV_ID: u64 = 0xE471_F1B7;

fn shared_disk_from(image: alloc::vec::Vec<u8>) -> Arc<dyn BlockDevice> {
    let cap = (image.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: image, ..Default::default() };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

/// Image with the PROJECT feature and a hidden project quota inode, but NOT
/// the QUOTA feature. Journalled quota options stay meaningful here.
fn project_disk() -> Arc<dyn BlockDevice> {
    let mut image = IMAGE.to_vec();
    let mut features = u32::from_le_bytes(image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4].try_into().unwrap());
    features |= EXT4_FEATURE_RO_COMPAT_PROJECT;
    image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4].copy_from_slice(&features.to_le_bytes());
    image[EXT4_PRJ_QUOTA_INUM_OFF..EXT4_PRJ_QUOTA_INUM_OFF + 4].copy_from_slice(&HELLO_INO.to_le_bytes());
    shared_disk_from(image)
}

/// The stock image: no PROJECT feature, no hidden quota inodes.
fn plain_disk() -> Arc<dyn BlockDevice> { shared_disk_from(IMAGE.to_vec()) }

/// PROJECT + QUOTA features with a seeded hidden project quota file.
fn hidden_quota_disk() -> Arc<dyn BlockDevice> {
    let disk = plain_disk();
    let m = ext4::rootfs::Ext4Mount::open(disk.clone()).expect("seed Ext4Mount::open");
    m.state().mount.write_at(HELLO_INO, 0, &empty_quota_file(PRJ_MAGIC)).expect("seed hidden quota file");
    drop(m);
    let mut image = IMAGE.to_vec();
    image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4]
        .copy_from_slice(&(EXT4_FEATURE_RO_COMPAT_QUOTA | EXT4_FEATURE_RO_COMPAT_PROJECT).to_le_bytes());
    image[EXT4_PRJ_QUOTA_INUM_OFF..EXT4_PRJ_QUOTA_INUM_OFF + 4].copy_from_slice(&HELLO_INO.to_le_bytes());
    let patched = shared_disk_from(image);
    let m = ext4::rootfs::Ext4Mount::open(patched.clone()).expect("seed patched Ext4Mount::open");
    m.state().mount.write_at(HELLO_INO, 0, &empty_quota_file(PRJ_MAGIC)).expect("seed hidden quota file");
    drop(m);
    patched
}

fn empty_quota_file(magic: u32) -> alloc::vec::Vec<u8> {
    let mut q = alloc::vec![0u8; QUOTA_FILE_BYTES];
    q[QF_MAGIC_OFF..QF_MAGIC_OFF + 4].copy_from_slice(&magic.to_le_bytes());
    q[QF_VERSION_OFF..QF_VERSION_OFF + 4].copy_from_slice(&V2_VERSION_V1.to_le_bytes());
    q[QF_FREE_BLK_OFF..QF_FREE_BLK_OFF + 4].copy_from_slice(&QUOTA_ROOT_BLOCK.to_le_bytes());
    q
}

/// Create `/aquota.user` holding an empty user quota file, then unmount.
fn seed_visible_user_quota_file(disk: &Arc<dyn BlockDevice>) -> u32 {
    let m = ext4::rootfs::Ext4Mount::open(disk.clone()).expect("seed mount");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, DEV_ID, String::from("ext4"));
    let f = m.state().create_at(b"/aquota.user", 0o600).expect("create visible quota file");
    let ino = f.ino() as u32;
    m.state().mount.write_at(ino, 0, &empty_quota_file(USR_MAGIC)).expect("seed visible quota file");
    drop(f); drop(sb); drop(m);
    ino
}

fn mount_opts(disk: Arc<dyn BlockDevice>, data: &str)
    -> vfs::KResult<(Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>)>
{
    let m = ext4::rootfs::Ext4Mount::open_with_data(disk, None, data)?;
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb_result(fs, root, DEV_ID, String::from("ext4"))?;
    Ok((m, sb))
}

#[test]
fn hidden_quota_without_a_quota_option_tracks_usage_but_enforces_nothing() {
    common::boot_hosted_pmm();
    let (_m, sb) = mount_opts(hidden_quota_disk(), "rw,relatime").expect("mount");
    let kind = vfs::QuotaType::Project;
    assert!(sb.s_dquot.is_enabled(kind), "hidden quota inode is always accounted");
    assert!(!sb.s_dquot.is_enforced(kind), "no prjquota option means no limit enforcement");
}

#[test]
fn prjquota_turns_hidden_project_quota_into_enforced_limits() {
    common::boot_hosted_pmm();
    let (_m, sb) = mount_opts(hidden_quota_disk(), "rw,prjquota").expect("mount");
    let kind = vfs::QuotaType::Project;
    assert!(sb.s_dquot.is_enabled(kind), "quota accounting enabled");
    assert!(sb.s_dquot.is_enforced(kind), "prjquota enforces project limits");
}

#[test]
fn a_quota_option_for_a_class_with_no_quota_file_enforces_nothing() {
    common::boot_hosted_pmm();
    // `usrquota` asks for user limits; this image carries no user quota inode,
    // so there is nothing to enable and the mount still succeeds.
    let (_m, sb) = mount_opts(hidden_quota_disk(), "rw,usrquota").expect("mount");
    assert!(!sb.s_dquot.is_enabled(vfs::QuotaType::User));
    assert!(!sb.s_dquot.is_enforced(vfs::QuotaType::Project), "prjquota was not asked for");
}

#[test]
fn prjquota_without_the_project_feature_fails_the_mount() {
    common::boot_hosted_pmm();
    assert_eq!(mount_opts(plain_disk(), "rw,prjquota").err(), Some(vfs::VfsError::Einval));
}

#[test]
fn prjquota_with_the_project_feature_mounts() {
    common::boot_hosted_pmm();
    mount_opts(project_disk(), "rw,prjquota").expect("project feature present");
}

#[test]
fn a_journalled_quota_file_option_loads_that_visible_file_at_mount() {
    common::boot_hosted_pmm();
    let disk = project_disk();
    let qino = seed_visible_user_quota_file(&disk);

    let (m, sb) = mount_opts(disk, "rw,usrjquota=aquota.user,jqfmt=vfsv1").expect("mount");

    let kind = vfs::QuotaType::User;
    assert!(sb.s_dquot.is_enabled(kind), "the named quota file is loaded at mount");
    assert_eq!(vfs::quota_getfmt(&sb, kind).expect("format"), vfs::QFMT_VFS_V1);
    assert_eq!(vfs::quota_getinfo(&sb, kind).expect("info").dqi_flags & vfs::DQF_SYS_FILE, 0,
        "a visible quota file is not a kernel-owned system file");
    assert!(sb.s_dquot.is_enforced(kind), "a journalled quota file brings limits with it");
    let raw = m.state().mount.read_inode(qino).expect("raw quota inode");
    assert_ne!(raw.i_flags & FS_IMMUTABLE_FL, 0, "the live quota file is protected immutable");
    assert_eq!(m.state().quota_opts().journalled_file(kind), Some(USR_QUOTA_FILE));
}

#[test]
fn a_named_quota_file_that_does_not_exist_does_not_fail_the_mount() {
    common::boot_hosted_pmm();
    let (_m, sb) = mount_opts(project_disk(), "rw,usrjquota=absent.user,jqfmt=vfsv1")
        .expect("a missing quota file must not make the filesystem unmountable");
    assert!(!sb.s_dquot.is_enabled(vfs::QuotaType::User));
}

#[test]
fn a_journalled_quota_file_without_a_format_fails_the_mount() {
    common::boot_hosted_pmm();
    assert_eq!(mount_opts(project_disk(), "rw,usrjquota=aquota.user").err(),
        Some(vfs::VfsError::Einval));
}

#[test]
fn a_quota_file_outside_the_filesystem_root_fails_the_mount() {
    common::boot_hosted_pmm();
    assert_eq!(mount_opts(project_disk(), "rw,usrjquota=sub/aquota.user,jqfmt=vfsv1").err(),
        Some(vfs::VfsError::Einval));
}

#[test]
fn mixing_a_quota_file_with_the_plain_option_of_another_class_fails_the_mount() {
    common::boot_hosted_pmm();
    assert_eq!(mount_opts(project_disk(), "rw,usrjquota=aquota.user,jqfmt=vfsv1,grpquota").err(),
        Some(vfs::VfsError::Einval));
}

#[test]
fn an_unknown_jqfmt_fails_the_mount() {
    common::boot_hosted_pmm();
    assert_eq!(mount_opts(project_disk(), "rw,jqfmt=vfsv9").err(), Some(vfs::VfsError::Einval));
}

#[test]
fn journalled_options_are_ignored_when_the_filesystem_owns_its_quota_inodes() {
    common::boot_hosted_pmm();
    let (m, sb) = mount_opts(hidden_quota_disk(), "rw,usrjquota=aquota.user,jqfmt=vfsv0,prjquota")
        .expect("journalled options are inert, not fatal, under the QUOTA feature");
    assert_eq!(m.state().quota_opts().journalled_file(vfs::QuotaType::User), None);
    assert_eq!(m.state().quota_opts().jquota_fmt, 0);
    assert!(sb.s_dquot.is_enforced(vfs::QuotaType::Project), "the plain option still applies");
}

#[test]
fn unknown_mount_options_never_fail_an_ext4_mount() {
    common::boot_hosted_pmm();
    // ext4 is the root filesystem: an option this driver does not model must
    // not turn a bootable disk into an unmountable one.
    let data = "rw,relatime,errors=remount-ro,data=ordered,discard,nobarrier,stripe=32";
    let (m, _sb) = mount_opts(project_disk(), data).expect("mount");
    assert_eq!(m.state().quota_opts(), ext4::SbQuotaOpts::default());
}

#[test]
fn noquota_leaves_hidden_quota_tracked_but_unenforced() {
    common::boot_hosted_pmm();
    // `noquota` clears limit enforcement; usage tracking of a kernel-owned
    // quota inode is a property of the filesystem, not of the mount options.
    let (_m, sb) = mount_opts(hidden_quota_disk(), "rw,prjquota,noquota").expect("mount");
    assert!(sb.s_dquot.is_enabled(vfs::QuotaType::Project));
    assert!(!sb.s_dquot.is_enforced(vfs::QuotaType::Project));
}
