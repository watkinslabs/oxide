//! fs-flags: `FileSystem::fs_flags()` is the type-level `file_system_type::
//! fs_flags` (Linux `include/linux/fs.h`). The `/proc/filesystems` `nodev`
//! column is DERIVED from `FS_REQUIRES_DEV` (`filesystems_proc_show`,
//! `fs/filesystems.c`) — not a hardcoded string. A block-backed fs emits
//! `"\t<name>\n"`; a pseudo / in-memory fs emits `"nodev\t<name>\n"`. The
//! rename-d_move predicate keys the VFS rename path off `FS_RENAME_DOES_D_MOVE`.

use std::sync::Arc;

use vfs::fs::{FileSystem, FsFlags};
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

struct TDir;
impl Inode for TDir {
    fn ino(&self) -> vfs::Ino { 1 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}

/// A pseudo / in-memory backend: no `fs_flags` override ⇒ `empty()`.
struct PseudoFs;
impl FileSystem for PseudoFs {
    fn name(&self) -> &str { "tmpfs" }
    fn root(&self) -> Option<InodeRef> { Some(Arc::new(TDir)) }
}

/// A block-device backed backend (ext4-shaped): `FS_REQUIRES_DEV`.
struct DiskFs;
impl FileSystem for DiskFs {
    fn name(&self) -> &str { "ext4" }
    fn fs_flags(&self) -> FsFlags { FsFlags::FS_REQUIRES_DEV }
    fn root(&self) -> Option<InodeRef> { Some(Arc::new(TDir)) }
}

/// A network fs that drives `d_move` itself (`FS_RENAME_DOES_D_MOVE`) and is
/// userns-mountable.
struct NetFs;
impl FileSystem for NetFs {
    fn name(&self) -> &str { "nfs" }
    fn fs_flags(&self) -> FsFlags {
        FsFlags::FS_REQUIRES_DEV | FsFlags::FS_RENAME_DOES_D_MOVE | FsFlags::FS_USERNS_MOUNT
    }
    fn root(&self) -> Option<InodeRef> { Some(Arc::new(TDir)) }
}

#[test]
fn default_fs_flags_is_empty_pseudo() {
    let fs = PseudoFs;
    assert_eq!(fs.fs_flags(), FsFlags::empty(), "default fs_flags() == empty()");
    assert!(!fs.requires_dev(), "pseudo fs is not block-device backed");
    assert!(!fs.rename_does_d_move(), "default has no FS_RENAME_DOES_D_MOVE");
}

#[test]
fn requires_dev_tracks_fs_requires_dev_bit() {
    assert!(DiskFs.requires_dev(), "ext4 sets FS_REQUIRES_DEV");
    assert!(!PseudoFs.requires_dev(), "tmpfs does not");
}

#[test]
fn proc_filesystems_line_derives_nodev_from_flags() {
    // filesystems_proc_show: nodev fs => "nodev\t<name>\n"; dev fs => "\t<name>\n".
    assert_eq!(PseudoFs.proc_filesystems_line(), "nodev\ttmpfs\n");
    assert_eq!(DiskFs.proc_filesystems_line(), "\text4\n");
}

#[test]
fn rename_does_d_move_predicate() {
    assert!(NetFs.rename_does_d_move(), "nfs handles d_move in ->rename");
    assert!(NetFs.fs_flags().contains(FsFlags::FS_USERNS_MOUNT), "nfs userns-mountable");
    // FS_REQUIRES_DEV co-set ⇒ no nodev tag even though it's a network fs.
    assert_eq!(NetFs.proc_filesystems_line(), "\tnfs\n");
}
