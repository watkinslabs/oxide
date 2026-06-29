//! inode-D28 (getattr half): `generic_fillattr` (Linux `fs/stat.c`) maps the
//! inode's stored *filesystem* uid/gid (`i_uid`/`i_gid`) THROUGH the mount
//! idmap to the *vfs* ids the caller sees, exactly the `vfs_getattr` →
//! `from_kuid`/`make_vfsuid` step. An identity (non-idmapped) mount returns the
//! raw fs ids unchanged; a real idmapped mount translates them, and an fs id
//! outside every extent surfaces as the INVALID sentinel (`(uid_t)-1`).
//!
//! Fails-before: a `generic_fillattr` that copied `inode.uid()`/`inode.gid()`
//! straight into `Kstat` (ignoring the idmap) would leak the on-disk owner of
//! an idmapped mount to the caller — a confinement hole. This pins the owner
//! columns of `stat` to the idmap output, not the raw fs ids.
//!
//! Pure value math over a minimal `Inode` + a local `Idmap` — no global state,
//! no QEMU, no serial guard.

use vfs::{FileType, Idmap, InodeBuilder, InodeRef, IDENTITY,
          default_file_ops, default_inode_ops, mk_mode};

/// Linux `(uid_t)-1`: the unmapped-owner sentinel for an extent miss.
const INVALID: u32 = u32::MAX;

/// Inode carrying explicit *filesystem* owner ids (the on-disk `i_uid`/`i_gid`).
fn owned_inode(uid: u32, gid: u32) -> InodeRef {
    InodeBuilder::new(9, mk_mode(FileType::Regular, 0), default_inode_ops(), default_file_ops())
        .owner(uid, gid).build()
}

// Identity mount: stat shows the raw fs owner unchanged (byte-identical to the
// pre-idmap path).
#[test]
fn identity_mount_shows_raw_owner() {
    let i = owned_inode(1000, 2000);
    let st = vfs::generic_fillattr(&i, &IDENTITY, None);
    assert_eq!(st.uid, 1000);
    assert_eq!(st.gid, 2000);
}

// Idmapped mount: the fs owner is translated to the vfs view (map_out).
#[test]
fn idmapped_mount_translates_owner() {
    // fs [0,65536) <-> vfs [100000,165536).
    let map = Idmap::uniform(0, 100_000, 65_536);
    let i = owned_inode(1000, 1500);
    let st = vfs::generic_fillattr(&i, &map, None);
    // raw fs 1000/1500 must NOT survive — they are mapped out to the vfs window.
    assert_eq!(st.uid, 101_000, "fs uid 1000 -> vfsuid 101000");
    assert_eq!(st.gid, 101_500, "fs gid 1500 -> vfsgid 101500");
}

// Idmapped mount, fs owner outside every extent -> INVALID, never a raw leak.
#[test]
fn idmapped_unmapped_owner_is_invalid() {
    let map = Idmap::uniform(0, 100_000, 65_536);
    let i = owned_inode(70_000, 70_000);
    let st = vfs::generic_fillattr(&i, &map, None);
    assert_eq!(st.uid, INVALID, "unmapped fs uid surfaces as (uid_t)-1, not 70000");
    assert_eq!(st.gid, INVALID);
}
