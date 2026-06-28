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

/// `S_IF*` file-type bits as the `u32` `Kstat`/stat-ABI surface. Re-derived
/// from the canonical `Umode` (`u16`) defs in `types` — single source of
/// truth, no duplicated magic literals. `mode` (`Kstat`) is `u32`, so these
/// stay `u32` for byte-identical OR-packing with the permission bits.
pub const S_IFMT:   u32 = crate::types::S_IFMT   as u32;
pub const S_IFSOCK: u32 = crate::types::S_IFSOCK as u32;
pub const S_IFLNK:  u32 = crate::types::S_IFLNK  as u32;
pub const S_IFREG:  u32 = crate::types::S_IFREG  as u32;
pub const S_IFBLK:  u32 = crate::types::S_IFBLK  as u32;
pub const S_IFDIR:  u32 = crate::types::S_IFDIR  as u32;
pub const S_IFCHR:  u32 = crate::types::S_IFCHR  as u32;
pub const S_IFIFO:  u32 = crate::types::S_IFIFO  as u32;

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

/// `new_encode_dev` (Linux `include/linux/kdev_t.h`): pack a `(major, minor)`
/// pair into the 32-bit `st_rdev` ABI surface with the huge-dev split — minor's
/// low 8 bits in `[0..8)`, the 12-bit major in `[8..20)`, and minor's HIGH bits
/// in `[20..32)`. The high-minor split is what lets a minor exceed 255 (e.g.
/// dynamic char minors, loop/dm devices) without clobbering the major field;
/// the naive `(major<<8)|minor` legacy form silently truncates those. Byte-
/// identical to `Devt::new(major, minor).raw()` — the one encoding every
/// `Inode::rdev()` impl reports, so `generic_fillattr` copies it through
/// verbatim for device nodes and reports 0 for everything else. # C: O(1)
pub const fn encode_dev(major: u32, minor: u32) -> u32 {
    (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12)
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
    // ONE place builds the `S_IFMT` half of the mode: `FileType::to_ifmt`
    // (shared with `Inode::i_mode`). `st_rdev` is only meaningful for device
    // nodes — Linux leaves it 0 for everything else.
    let type_bits: u32 = ft.to_ifmt() as u32;
    let rdev: u32 = match ft {
        FileType::CharDev | FileType::BlockDev => inode.rdev(),
        _ => 0,
    };
    let perm = inode.perm()
        .or_else(|| if ov.owner_set && ov.mode_bits != 0 { Some(ov.mode_bits) } else { None })
        .unwrap_or_else(|| default_perm_for(ft));
    let raw_uid = inode.uid().unwrap_or(if ov.owner_set { ov.uid } else { 0 });
    let raw_gid = inode.gid().unwrap_or(if ov.owner_set { ov.gid } else { 0 });
    // `st_blksize` is a SUPERBLOCK property (Linux `s_blocksize`), not a
    // per-inode one: route through the owning SB so every inode on one fs
    // reports its mount's block size. `blksize()` is only the fallback for
    // SB-less anon inodes (pidfd/pipe/socket — pending D35's anon SB). The same
    // effective allocation unit also drives `st_blocks` (see `blocks_for`).
    let bsize: u32 = inode.i_sb().map(|s| s.s_blocksize).unwrap_or_else(|| inode.blksize());
    Kstat {
        ino:      inode.ino(),
        mode:     type_bits | perm as u32,
        nlink:    inode.nlink(),
        uid:      idmap.map_out_uid(raw_uid),
        gid:      idmap.map_out_gid(raw_gid),
        rdev,
        size:     inode.size(),
        blksize:  bsize,
        blocks:   blocks_for(inode.size(), bsize),
        atime_ns: inode.atime().unwrap_or(ov.atime_ns),
        mtime_ns: inode.mtime().unwrap_or(ov.mtime_ns),
        ctime_ns: inode.ctime().unwrap_or(ov.ctime_ns),
        fsid:     inode.fsid(),
    }
}

/// `st_blocks` (Linux `stat.st_blocks`): the count of 512-byte units the file
/// occupies. With no stored `i_blocks` field (D20 remainder), the best generic
/// estimate of a NON-sparse file is `size` rounded UP to the filesystem
/// allocation unit (`s_blocksize`/`blksize`) and re-expressed in 512-byte
/// sectors — so a sub-block file reports a whole block (a 1-byte file on a 4 KiB
/// fs = 8 sectors), matching `stat(1)` on ext4/tmpfs instead of the
/// `ceil(size/512)` under-count that reported a single sector. Sparse /
/// preallocated extents still need a real per-inode `i_blocks` (and `i_bytes`)
/// to be exact — that is the unaddressed half of D20. # C: O(1)
pub fn blocks_for(size: u64, bsize: u32) -> u64 {
    let unit = (bsize as u64).max(512);          // allocation unit, ≥ one sector
    let units = (size + unit - 1) / unit;         // blocks occupied, rounded up
    units * (unit / 512)                          // → 512-byte sectors
}

/// `vfs_getattr` (Linux `fs/stat.c`): the stat-family entry that dispatches to
/// `i_op->getattr` (override) or `generic_fillattr` (default). # C: O(1)
pub fn vfs_getattr(inode: &crate::inode::InodeRef, idmap: &Idmap, overlay: Option<InodeTimes>) -> Kstat {
    inode.getattr(idmap, overlay)
}
