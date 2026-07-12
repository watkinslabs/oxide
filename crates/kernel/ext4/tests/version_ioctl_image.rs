//! `EXT4_IOC_GETVERSION` / `EXT4_IOC_SETVERSION` backend coverage over a real
//! ext4 image. Usercopy lives in the syscall crate; this proves the filesystem
//! `file_operations->unlocked_ioctl` side.

extern crate alloc;
mod common;
use alloc::string::String;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;
use vfs::{Dentry, File, FileIoctlCmd, FileIoctlReply, OpenFlags, SuperBlock, VfsError};

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const MINI: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;
const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
const EXT4_RO_COMPAT_OFF: usize = EXT4_SUPERBLOCK_OFFSET + 0x64;
const RO_COMPAT_METADATA_CSUM: u32 = ext4::superblock::RO_COMPAT_METADATA_CSUM;
const RO_COMPAT_METADATA_CSUM_SEED: u32 = ext4::superblock::RO_COMPAT_METADATA_CSUM_SEED;

fn shared_disk_from(image: Vec<u8>) -> Arc<dyn BlockDevice> {
    let cap = (image.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32, buffer: image,
    };
    disk.submit_sync(&mut req).expect("seed memdisk");
    disk
}

fn shared_disk() -> Arc<dyn BlockDevice> {
    shared_disk_from(IMAGE.to_vec())
}

fn shared_mini_disk() -> Arc<dyn BlockDevice> {
    shared_disk_from(MINI.to_vec())
}

fn no_metadata_csum_disk() -> Arc<dyn BlockDevice> {
    let mut image = IMAGE.to_vec();
    let mut ro = u32::from_le_bytes(
        image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4].try_into().unwrap(),
    );
    ro &= !(RO_COMPAT_METADATA_CSUM | RO_COMPAT_METADATA_CSUM_SEED);
    image[EXT4_RO_COMPAT_OFF..EXT4_RO_COMPAT_OFF + 4].copy_from_slice(&ro.to_le_bytes());
    shared_disk_from(image)
}

fn mount(disk: Arc<dyn BlockDevice>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    common::boot_hosted_pmm();
    let m = ext4::rootfs::Ext4Mount::open(disk).expect("Ext4Mount::open");
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let sb = common::realize_sb(fs, root, 0xE471_F1A8, String::from("ext4"));
    (m, sb)
}

fn open_file(inode: vfs::InodeRef) -> Arc<File> {
    let dentry = Dentry::new_root(inode.clone());
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

#[test]
fn getversion_reports_on_disk_generation() {
    let disk = shared_disk();
    let (m, _sb) = mount(disk);
    let inode = m.state().create_at(b"/version-get.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/version-get.txt").expect("lookup");
    let file = open_file(inode);
    let want = m.state().mount.read_inode(ino).unwrap().generation;

    assert_eq!(
        file.unlocked_ioctl(&vfs::IDENTITY, &vfs::Cred::root(), FileIoctlCmd::GetVersion),
        Ok(FileIoctlReply::U32(want)),
    );
}

#[test]
fn setversion_rejects_metadata_csum_like_linux() {
    let disk = shared_mini_disk();
    let (m, _sb) = mount(disk);
    let inode = m.state().create_at(b"/version-csum.txt", 0o644).expect("create");
    let file = open_file(inode);

    assert_eq!(
        file.unlocked_ioctl(&vfs::IDENTITY, &vfs::Cred::root(), FileIoctlCmd::SetVersionPrepare),
        Err(VfsError::Enotty),
    );
}

#[test]
fn setversion_requires_owner_or_cap_fowner() {
    let disk = no_metadata_csum_disk();
    let (m, _sb) = mount(disk);
    let inode = m.state().create_at(b"/version-owner.txt", 0o644).expect("create");
    let file = open_file(inode);
    let mut cred = vfs::Cred::root();
    cred.uid = 1000;
    cred.cap_fowner = false;

    assert_eq!(
        file.unlocked_ioctl(&vfs::IDENTITY, &cred, FileIoctlCmd::SetVersionPrepare),
        Err(VfsError::Eperm),
    );
}

#[test]
fn setversion_persists_generation_and_updates_ctime() {
    let disk = no_metadata_csum_disk();
    let (m, sb) = mount(disk.clone());
    let inode = m.state().create_at(b"/version-set.txt", 0o644).expect("create");
    let ino = m.state().mount.lookup_path(b"/version-set.txt").expect("lookup");
    let file = open_file(inode.clone());
    let before_ctime = inode.ctime().unwrap_or(0);
    let before_version = vfs::inode::inode_query_iversion(&inode);

    file.unlocked_ioctl(&vfs::IDENTITY, &vfs::Cred::root(), FileIoctlCmd::SetVersionPrepare)
        .expect("prepare");
    file.unlocked_ioctl(&vfs::IDENTITY, &vfs::Cred::root(), FileIoctlCmd::SetVersion(0x1234_5678))
        .expect("setversion");
    assert_eq!(m.state().mount.read_inode(ino).unwrap().generation, 0x1234_5678);
    assert!(inode.ctime().unwrap_or(0) >= before_ctime);
    assert!(vfs::inode::inode_query_iversion(&inode) > before_version);

    drop(file); drop(inode); drop(sb); drop(m);
    let (m2, _sb2) = mount(disk);
    let ino2 = m2.state().mount.lookup_path(b"/version-set.txt").expect("lookup after remount");
    assert_eq!(m2.state().mount.read_inode(ino2).unwrap().generation, 0x1234_5678);
}
