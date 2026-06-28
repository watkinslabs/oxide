//! Per-mount id mapping (Linux `struct mnt_idmap` / `uid_gid_map`).
//!
//! Identity by default (the `nop` map, Linux `nop_mnt_idmap`): a non-idmapped
//! mount maps every id to itself, so stat-out and chown/create-in are
//! byte-identical to the non-idmapped kernel — the no-op that keeps boot
//! unaffected. An idmapped mount (`mount_setattr(MOUNT_ATTR_IDMAP)`) installs
//! extents translating filesystem ids (`i_uid`/`i_gid`) to/from the ids the
//! caller observes (`vfsuid`/`vfsgid`): `map_out_*` at stat-out, `map_in_*` at
//! chown/create-in. A real idmap yields `INVALID_ID` for any id outside its
//! extents (Linux `map_id_down`/`map_id_up` → `(u32)-1`), never a passthrough.

extern crate alloc;
use alloc::vec::Vec;

/// Linux `(uid_t)-1` / `(gid_t)-1`: the INVALID owner sentinel a real (non-nop)
/// idmap yields for any id outside every extent. `make_vfsuid`/`from_vfsuid`
/// (`fs/mnt_idmapping.c`) propagate `map_id_down`/`map_id_up`'s `(u32)-1` miss
/// result as `INVALID_VFSUID`/`INVALID_UID`; the userspace copy-out boundary
/// later munges it to overflowuid (65534).
pub const INVALID_ID: u32 = u32::MAX;

/// One id-translation extent (Linux `uid_gid_extent`): the half-open fs-id
/// range `[fs_lo, fs_lo+count)` corresponds to vfs-id range
/// `[vfs_lo, vfs_lo+count)`.
#[derive(Clone, Copy)]
pub struct IdExtent { pub fs_lo: u32, pub vfs_lo: u32, pub count: u32 }

/// Per-mount idmap. `nop` marks the non-idmapped map (Linux `nop_mnt_idmap`),
/// which passes every id through verbatim. A real idmap (`nop == false`)
/// translates through its extents and yields `INVALID_ID` on a miss — so an
/// empty extent list on a real idmap maps *every* id to INVALID, matching a
/// user namespace with an empty `uid_map`/`gid_map`.
pub struct Idmap {
    nop: bool,
    uid_ext: Vec<IdExtent>,
    gid_ext: Vec<IdExtent>,
}

/// The shared no-op map. Every `map_*` returns its input.
pub static IDENTITY: Idmap = Idmap { nop: true, uid_ext: Vec::new(), gid_ext: Vec::new() };

impl Idmap {
    /// No-op / identity map (Linux `nop_mnt_idmap`). # C: O(1)
    pub const fn identity() -> Idmap { Idmap { nop: true, uid_ext: Vec::new(), gid_ext: Vec::new() } }

    /// Build a real idmap from explicit uid/gid extent lists. # C: O(1)
    pub fn new(uid_ext: Vec<IdExtent>, gid_ext: Vec<IdExtent>) -> Idmap { Idmap { nop: false, uid_ext, gid_ext } }

    /// Real idmap with one extent on both uid and gid
    /// (`[fs_lo,+count) <-> [vfs_lo,+count)`). # C: O(1)
    pub fn uniform(fs_lo: u32, vfs_lo: u32, count: u32) -> Idmap {
        let e = IdExtent { fs_lo, vfs_lo, count };
        Idmap { nop: false, uid_ext: alloc::vec![e], gid_ext: alloc::vec![e] }
    }

    /// True for the no-op (non-idmapped) map. # C: O(1)
    pub fn is_identity(&self) -> bool { self.nop }

    /// fs-id → vfs-id; INVALID on an extent miss in a real idmap. # C: O(extents)
    fn out(&self, ext: &[IdExtent], fs: u32) -> u32 {
        if self.nop { return fs; }
        for e in ext { if fs >= e.fs_lo && (fs - e.fs_lo) < e.count { return e.vfs_lo + (fs - e.fs_lo); } }
        INVALID_ID
    }
    /// vfs-id → fs-id; INVALID on an extent miss in a real idmap. # C: O(extents)
    fn inn(&self, ext: &[IdExtent], vfs: u32) -> u32 {
        if self.nop { return vfs; }
        for e in ext { if vfs >= e.vfs_lo && (vfs - e.vfs_lo) < e.count { return e.fs_lo + (vfs - e.vfs_lo); } }
        INVALID_ID
    }

    /// fs `i_uid` → vfsuid shown through stat (identity ⇒ unchanged). # C: O(extents)
    pub fn map_out_uid(&self, fs: u32) -> u32 { self.out(&self.uid_ext, fs) }
    /// fs `i_gid` → vfsgid shown through stat. # C: O(extents)
    pub fn map_out_gid(&self, fs: u32) -> u32 { self.out(&self.gid_ext, fs) }
    /// vfsuid (chown/create arg) → fs `i_uid` stored. # C: O(extents)
    pub fn map_in_uid(&self, vfs: u32) -> u32 { self.inn(&self.uid_ext, vfs) }
    /// vfsgid (chown/create arg) → fs `i_gid` stored. # C: O(extents)
    pub fn map_in_gid(&self, vfs: u32) -> u32 { self.inn(&self.gid_ext, vfs) }
}
