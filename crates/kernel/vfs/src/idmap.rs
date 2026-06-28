//! Per-mount id mapping (Linux `struct mnt_idmap` / `uid_gid_map`).
//!
//! Identity by default (empty extents): a non-idmapped mount maps every id to
//! itself, so stat-out and chown/create-in are byte-identical to the
//! non-idmapped kernel — the no-op that keeps boot unaffected. An idmapped
//! mount (`mount_setattr(MOUNT_ATTR_IDMAP)`) installs extents translating
//! filesystem ids (`i_uid`/`i_gid`) to/from the ids the caller observes
//! (`vfsuid`/`vfsgid`): `map_out_*` at stat-out, `map_in_*` at chown/create-in.

extern crate alloc;
use alloc::vec::Vec;

/// One id-translation extent (Linux `uid_gid_extent`): the half-open fs-id
/// range `[fs_lo, fs_lo+count)` corresponds to vfs-id range
/// `[vfs_lo, vfs_lo+count)`.
#[derive(Clone, Copy)]
pub struct IdExtent { pub fs_lo: u32, pub vfs_lo: u32, pub count: u32 }

/// Per-mount idmap. Empty `uid_ext`/`gid_ext` == identity.
pub struct Idmap {
    uid_ext: Vec<IdExtent>,
    gid_ext: Vec<IdExtent>,
}

/// The shared identity map (no extents). Every `map_*` returns its input.
pub static IDENTITY: Idmap = Idmap { uid_ext: Vec::new(), gid_ext: Vec::new() };

impl Idmap {
    /// Identity map (no extents). # C: O(1)
    pub const fn identity() -> Idmap { Idmap { uid_ext: Vec::new(), gid_ext: Vec::new() } }

    /// Build from explicit uid/gid extent lists. # C: O(1)
    pub fn new(uid_ext: Vec<IdExtent>, gid_ext: Vec<IdExtent>) -> Idmap { Idmap { uid_ext, gid_ext } }

    /// One extent applied to both uid and gid (`[fs_lo,+count) <-> [vfs_lo,+count)`).
    /// # C: O(1)
    pub fn uniform(fs_lo: u32, vfs_lo: u32, count: u32) -> Idmap {
        let e = IdExtent { fs_lo, vfs_lo, count };
        Idmap { uid_ext: alloc::vec![e], gid_ext: alloc::vec![e] }
    }

    /// True for the no-op (non-idmapped) map. # C: O(1)
    pub fn is_identity(&self) -> bool { self.uid_ext.is_empty() && self.gid_ext.is_empty() }

    /// # C: O(extents)
    fn out(ext: &[IdExtent], fs: u32) -> u32 {
        for e in ext { if fs >= e.fs_lo && (fs - e.fs_lo) < e.count { return e.vfs_lo + (fs - e.fs_lo); } }
        fs
    }
    /// # C: O(extents)
    fn inn(ext: &[IdExtent], vfs: u32) -> u32 {
        for e in ext { if vfs >= e.vfs_lo && (vfs - e.vfs_lo) < e.count { return e.fs_lo + (vfs - e.vfs_lo); } }
        vfs
    }

    /// fs `i_uid` → vfsuid shown through stat (identity ⇒ unchanged). # C: O(extents)
    pub fn map_out_uid(&self, fs: u32) -> u32 { Self::out(&self.uid_ext, fs) }
    /// fs `i_gid` → vfsgid shown through stat. # C: O(extents)
    pub fn map_out_gid(&self, fs: u32) -> u32 { Self::out(&self.gid_ext, fs) }
    /// vfsuid (chown/create arg) → fs `i_uid` stored. # C: O(extents)
    pub fn map_in_uid(&self, vfs: u32) -> u32 { Self::inn(&self.uid_ext, vfs) }
    /// vfsgid (chown/create arg) → fs `i_gid` stored. # C: O(extents)
    pub fn map_in_gid(&self, vfs: u32) -> u32 { Self::inn(&self.gid_ext, vfs) }
}
