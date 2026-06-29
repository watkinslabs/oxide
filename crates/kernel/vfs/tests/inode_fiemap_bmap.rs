//! `Inode::fiemap`/`bmap`/`fileattr_get`/`fileattr_set` (Linux `i_op->fiemap`,
//! `bmap()`, `i_op->fileattr_{get,set}`). Before this the extent-mapping ops
//! existed nowhere (grep fiemap/bmap/fileattr = nothing), so `FS_IOC_FIEMAP`,
//! `FIBMAP`, and `chattr`/`lsattr` had no inode entry point. This proves: the
//! trait defaults match Linux's "no op installed" errno (`EOPNOTSUPP` for
//! fiemap/fileattr, `EINVAL` for bmap); a backend can emit extents through the
//! callback and stop early; and `FileAttr::from_i_flags` maps the VFS `S_*`
//! word onto the `FS_*_FL` chattr view (the inverse of `ext4_set_inode_flags`).

use vfs::inode::{
    FileAttr, FiemapExtent, Inode, FIEMAP_EXTENT_LAST, FS_APPEND_FL, FS_IMMUTABLE_FL,
    FS_NOATIME_FL, FS_SYNC_FL, S_APPEND, S_IMMUTABLE, S_NOATIME, S_SYNC,
};
use vfs::{FileType, InodeRef, KResult, VfsError};

/// Plain inode: every extent-mapping op uses the trait default.
struct Plain;
impl Inode for Plain {
    fn ino(&self) -> vfs::Ino { 1 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 8192 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// Two-extent file that reports its layout through `fiemap` and resolves blocks
/// through `bmap`. Block 0 is a hole (returns 0); blocks 1..2 are allocated.
struct Mapped;
impl Inode for Mapped {
    fn ino(&self) -> vfs::Ino { 2 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 8192 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn bmap(&self, block: u64) -> KResult<u64> {
        Ok(if block == 0 { 0 } else { 1000 + block }) // hole at 0, else mapped
    }
    fn fiemap(
        &self,
        _start: u64,
        _len: u64,
        emit: &mut dyn FnMut(FiemapExtent) -> bool,
    ) -> KResult<()> {
        let exts = [
            FiemapExtent { logical: 0, physical: 4096 * 1001, length: 4096, flags: 0 },
            FiemapExtent { logical: 4096, physical: 4096 * 1002, length: 4096, flags: FIEMAP_EXTENT_LAST },
        ];
        for e in exts { if !emit(e) { break; } }
        Ok(())
    }
}

/// Trait defaults: Linux returns EOPNOTSUPP for an inode with no `->fiemap`
/// and no `->fileattr_*`, and EINVAL for `bmap` with no `->bmap` op.
#[test]
fn defaults_match_linux_errno() {
    let p = Plain;
    let mut seen = false;
    assert_eq!(p.fiemap(0, p.size(), &mut |_| { seen = true; true }), Err(VfsError::Eopnotsupp));
    assert!(!seen, "default fiemap emits no extents");
    assert_eq!(p.bmap(0), Err(VfsError::Einval));
    assert_eq!(p.fileattr_get(), Err(VfsError::Eopnotsupp));
    assert_eq!(p.fileattr_set(&FileAttr::default()), Err(VfsError::Eopnotsupp));
}

/// A backend emits its extents in order, and the final extent carries
/// `FIEMAP_EXTENT_LAST`.
#[test]
fn fiemap_emits_extents_in_order() {
    let m = Mapped;
    let mut out = Vec::new();
    assert_eq!(m.fiemap(0, m.size(), &mut |e| { out.push(e); true }), Ok(()));
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].logical, 0);
    assert_eq!(out[1].logical, 4096);
    assert_eq!(out[1].flags & FIEMAP_EXTENT_LAST, FIEMAP_EXTENT_LAST);
    assert_eq!(out[0].flags & FIEMAP_EXTENT_LAST, 0);
}

/// `emit` returning `false` stops the walk early (caller's buffer is full,
/// Linux `fiemap_fill_next_extent` returning 1).
#[test]
fn fiemap_stops_when_callback_full() {
    let m = Mapped;
    let mut out = Vec::new();
    assert_eq!(m.fiemap(0, m.size(), &mut |e| { out.push(e); false }), Ok(()));
    assert_eq!(out.len(), 1, "callback returned false after the first extent");
}

/// `bmap` distinguishes a hole (physical 0) from an allocated block.
#[test]
fn bmap_reports_hole_and_block() {
    let m = Mapped;
    assert_eq!(m.bmap(0), Ok(0), "block 0 is a hole");
    assert_eq!(m.bmap(1), Ok(1001));
    assert_eq!(m.bmap(2), Ok(1002));
}

/// `FileAttr::from_i_flags` maps the VFS-representable `S_*` bits onto the
/// `FS_*_FL` chattr view and leaves FS-private bits clear.
#[test]
fn fileattr_from_i_flags_maps_vfs_bits() {
    let fa = FileAttr::from_i_flags(S_IMMUTABLE | S_APPEND | S_NOATIME | S_SYNC);
    assert_eq!(fa.flags, FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NOATIME_FL | FS_SYNC_FL);
    assert_eq!(fa.fsx_xflags, 0);
    assert_eq!(fa.fsx_projid, 0);
    // No VFS flags ⇒ empty view.
    assert_eq!(FileAttr::from_i_flags(0), FileAttr::default());
    // A single bit maps to a single FS_*_FL bit.
    assert_eq!(FileAttr::from_i_flags(S_IMMUTABLE).flags, FS_IMMUTABLE_FL);
}
