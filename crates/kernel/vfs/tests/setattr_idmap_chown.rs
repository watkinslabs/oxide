//! inode-D28 (setattr half): `setattr_prepare`/`simple_setattr` (Linux
//! `fs/attr.c`) decide ownership against the inode's *vfs* owner — the fs
//! `i_uid`/`i_gid` mapped OUT through the mount idmap — and store a chown's
//! target id mapped back IN to the fs view. On an idmapped mount the fs owner
//! (e.g. 1000) is NOT the caller's view (e.g. vfs 101000); the DAC owner test
//! and the stored id both have to go through the idmap or chmod/chown on an
//! idmapped mount mis-authorize and persist the wrong on-disk owner.
//!
//! Fails-before: comparing `cred.uid` to the raw `inode.uid()` (no `map_out`)
//! would deny the genuine vfs owner a chmod and grant a stranger; storing
//! `ia.uid` raw (no `map_in`) would write the caller's vfs id as the on-disk
//! `i_uid`. This pins both directions of the idmap through the attr path.
//!
//! Local `Idmap` + a recording `Inode`; no global state, no serial guard.

use std::sync::atomic::{AtomicU32, Ordering};

use vfs::inode::Inode;
use vfs::setattr::{notify_change, setattr_prepare, simple_setattr, Iattr, ATTR_MODE, ATTR_UID};
use vfs::{Cred, FileType, Idmap, InodeRef, KResult, VfsError, CRED_NGROUPS};

/// Inode whose owner is mutable so a chown apply is observable. `uid`/`gid` are
/// FILESYSTEM ids (the on-disk `i_uid`/`i_gid`).
struct RecInode { uid: AtomicU32, gid: AtomicU32, perm: AtomicU32 }
impl RecInode {
    fn new(uid: u32, gid: u32) -> Self {
        RecInode { uid: AtomicU32::new(uid), gid: AtomicU32::new(gid), perm: AtomicU32::new(0o644) }
    }
}
impl Inode for RecInode {
    fn ino(&self) -> vfs::Ino { 1 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn perm(&self) -> Option<u16> { Some(self.perm.load(Ordering::Relaxed) as u16) }
    fn uid(&self) -> Option<u32> { Some(self.uid.load(Ordering::Relaxed)) }
    fn gid(&self) -> Option<u32> { Some(self.gid.load(Ordering::Relaxed)) }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn set_perm(&self, perm: u16) -> KResult<()> { self.perm.store(perm as u32, Ordering::Relaxed); Ok(()) }
    fn set_owner(&self, uid: u32, gid: u32) -> KResult<()> {
        self.uid.store(uid, Ordering::Relaxed); self.gid.store(gid, Ordering::Relaxed); Ok(())
    }
}

/// Unprivileged cred with the given vfs uid (no CAP_* set).
fn user(uid: u32) -> Cred {
    Cred {
        uid, gid: uid,
        cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        ngroups: 0, groups: [0u32; CRED_NGROUPS],
    }
}

/// idmap: fs [0,65536) <-> vfs [100000,165536). fs uid 1000 == vfs uid 101000.
fn idmap() -> Idmap { Idmap::uniform(0, 100_000, 65_536) }

// The vfs owner (uid 101000) may chmod an inode whose fs i_uid is 1000 — the
// owner test goes through map_out, not a raw fs-id compare.
#[test]
fn vfs_owner_may_chmod_idmapped_inode() {
    let inode: InodeRef = std::sync::Arc::new(RecInode::new(1000, 1000));
    let mut ia = Iattr { valid: ATTR_MODE, mode: 0o600, ..Default::default() };
    // the genuine vfs owner (101000) succeeds...
    assert!(setattr_prepare(&idmap(), &inode, &mut ia, &user(101_000)).is_ok());
    // ...while the RAW fs id (1000) — which is NOT the vfs owner — is denied.
    let mut ia2 = Iattr { valid: ATTR_MODE, mode: 0o600, ..Default::default() };
    assert_eq!(setattr_prepare(&idmap(), &inode, &mut ia2, &user(1000)), Err(VfsError::Eperm),
        "raw fs id is not the vfs owner on an idmapped mount");
}

// A chown stores the target vfs id mapped BACK to the fs view (map_in): chown
// to vfs 102000 must persist on-disk i_uid 2000, not 102000.
#[test]
fn chown_stores_fs_mapped_id() {
    let rec = std::sync::Arc::new(RecInode::new(1000, 1000));
    let inode: InodeRef = rec.clone();
    // CAP_CHOWN cred to authorize the uid change; target is the vfs id 102000.
    let mut ia = Iattr { valid: ATTR_UID, uid: 102_000, ..Default::default() };
    notify_change(&idmap(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(rec.uid.load(Ordering::Relaxed), 2000,
        "stored i_uid = map_in(102000) = 2000, not the raw vfs id");
}

// Direct simple_setattr (the apply primitive) also maps in: vfs 165535 (top of
// window) -> fs 65535; an unmapped vfs id stores INVALID, never the raw id.
#[test]
fn simple_setattr_maps_in_owner() {
    let rec = std::sync::Arc::new(RecInode::new(1000, 1000));
    let ia = Iattr { valid: ATTR_UID, uid: 165_535, ..Default::default() };
    simple_setattr(rec.as_ref(), &idmap(), &ia).unwrap();
    assert_eq!(rec.uid.load(Ordering::Relaxed), 65_535, "map_in(165535) = fs 65535");
}
