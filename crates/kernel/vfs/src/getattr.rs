//! `vfs_getattr` / `generic_fillattr` (Linux `fs/stat.c`).
//!
//! A single `Inode::getattr` inode-op (default `generic_fillattr`) assembles
//! the `Kstat` every stat-family syscall encodes, replacing the field-by-field
//! `S_IF*` mapping + overlay-merge + perm-fallback duplicated across
//! stat/lstat/fstat/newfstatat/statx. Backends that carry native metadata
//! (ext4) override `getattr`; pseudo-fs use the default.

extern crate alloc;
use crate::idmap::Idmap;
use crate::inode::Inode;
use crate::inode_times::InodeTimes;
use crate::types::FileType;

/// `S_IF*` file-type bits (Linux `include/uapi/linux/stat.h`).
pub const S_IFMT:   u32 = 0o170000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFLNK:  u32 = 0o120000;
pub const S_IFREG:  u32 = 0o100000;
pub const S_IFBLK:  u32 = 0o060000;
pub const S_IFDIR:  u32 = 0o040000;
pub const S_IFCHR:  u32 = 0o020000;
pub const S_IFIFO:  u32 = 0o010000;

/// Resolved inode attributes (Linux `struct kstat`). `mode` carries the
/// `S_IF*` type bits OR'd with the permission bits. `fsid` is the raw
/// filesystem identity (`Inode::fsid`); the syscall layer encodes it into the
/// ABI `dev_t`.
#[derive(Clone, Copy, Default)]
pub struct Kstat {
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub size: u64,
    pub blksize: u32,
    pub blocks: u64,
    pub atime_ns: u64,
    pub mtime_ns: u64,
    pub ctime_ns: u64,
    pub fsid: u64,
}

/// Linux-shaped permission fallback for inodes without a native mode
/// (`Inode::perm() == None` and no overlay). # C: O(1)
pub fn default_perm_for(ft: FileType) -> u16 {
    match ft {
        FileType::Directory => 0o755,
        FileType::Symlink   => 0o777,
        FileType::CharDev | FileType::BlockDev => 0o666,
        FileType::Fifo | FileType::Socket => 0o666,
        FileType::Regular   => 0o644,
    }
}

/// `generic_fillattr` — assemble a `Kstat` from inode fields, merging the
/// kernel `inode_times` overlay (perm/owner/times for pseudo-fs without native
/// storage) and applying the mount `idmap` to the owner ids. An identity idmap
/// returns the raw fs ids, so the output is byte-identical to the
/// pre-idmap stat path. # C: O(1)
pub fn generic_fillattr<I: Inode + ?Sized>(inode: &I, idmap: &Idmap, overlay: Option<InodeTimes>) -> Kstat {
    let ov = overlay.unwrap_or_default();
    let ft = inode.file_type();
    let (type_bits, rdev): (u32, u32) = match ft {
        FileType::CharDev   => (S_IFCHR,  inode.rdev()),
        FileType::BlockDev  => (S_IFBLK,  inode.rdev()),
        FileType::Directory => (S_IFDIR,  0),
        FileType::Regular   => (S_IFREG,  0),
        FileType::Symlink   => (S_IFLNK,  0),
        FileType::Fifo      => (S_IFIFO,  0),
        FileType::Socket    => (S_IFSOCK, 0),
    };
    let perm = inode.perm()
        .or_else(|| if ov.owner_set && ov.mode_bits != 0 { Some(ov.mode_bits) } else { None })
        .unwrap_or_else(|| default_perm_for(ft));
    let raw_uid = inode.uid().unwrap_or(if ov.owner_set { ov.uid } else { 0 });
    let raw_gid = inode.gid().unwrap_or(if ov.owner_set { ov.gid } else { 0 });
    Kstat {
        ino:      inode.ino(),
        mode:     type_bits | perm as u32,
        nlink:    inode.nlink(),
        uid:      idmap.map_out_uid(raw_uid),
        gid:      idmap.map_out_gid(raw_gid),
        rdev,
        size:     inode.size(),
        blksize:  inode.blksize(),
        blocks:   (inode.size() + 511) / 512,
        atime_ns: inode.atime().unwrap_or(ov.atime_ns),
        mtime_ns: inode.mtime().unwrap_or(ov.mtime_ns),
        ctime_ns: inode.ctime().unwrap_or(ov.ctime_ns),
        fsid:     inode.fsid(),
    }
}

/// `vfs_getattr` (Linux `fs/stat.c`): the stat-family entry that dispatches to
/// `i_op->getattr` (override) or `generic_fillattr` (default). # C: O(1)
pub fn vfs_getattr(inode: &crate::inode::InodeRef, idmap: &Idmap, overlay: Option<InodeTimes>) -> Kstat {
    inode.getattr(idmap, overlay)
}
