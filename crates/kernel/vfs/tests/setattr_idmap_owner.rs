//! `setattr_prepare` owner gate on an IDMAPPED mount (Linux `fs/attr.c`
//! `setattr_prepare` → `inode_owner_or_capable` → `vfsuid_has_mapping`). The
//! chmod / specific-time-utimes owner branch must reduce to
//! `inode_owner_or_capable`, NOT the open-coded `uid == vfsuid || cap_fowner`:
//! when an idmapped mount's extents do not cover the inode's fs owner, the
//! inode vfsuid is INVALID and a CAP_FOWNER caller must be DENIED — privilege
//! cannot be exercised over an owner that has no mapping in the caller's
//! namespace.
//!
//! Fails-before: the inline `cred.cap_fowner` short-circuit granted the chmod
//! over an unmapped-owner inode (EPERM expected, Ok returned). Passes-after:
//! the migrated `inode_owner_or_capable` denies it. Identity mounts and mapped
//! owners are the positive controls (unchanged behaviour).

use vfs::setattr::{setattr_prepare, Iattr, ATTR_MODE};
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder};
use vfs::{Cred, FileType, IdExtent, Idmap, InodeRef, VfsError};

/// Inode carrying an explicit fs owner uid/gid (the on-disk id, pre-idmap),
/// perm 0o644.
fn node(uid: u32, gid: u32) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .owner(uid, gid).build()
}

/// Cred with capabilities chosen per test.
fn cred(uid: u32, cap_fowner: bool) -> Cred {
    Cred { uid, gid: 0,
        cap_dac_override: false, cap_dac_read_search: false, cap_fowner,
        cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty() }
}

/// A real idmap mapping fs ids [1000,1010) ↔ vfs ids [0,10). An inode owned by
/// fs uid 5000 is OUTSIDE the extents, so its vfsuid is INVALID.
fn idmapped() -> Idmap {
    let e = IdExtent { fs_lo: 1000, vfs_lo: 0, count: 10 };
    Idmap::new(vec![e], vec![e])
}

fn chmod() -> Iattr { Iattr { valid: ATTR_MODE, mode: 0o600, ..Default::default() } }

/// THE regression: CAP_FOWNER caller, idmapped mount, inode owner unmapped
/// (vfsuid == INVALID) → chmod owner gate must be EPERM (was Ok before the
/// migration to `inode_owner_or_capable`).
#[test]
fn cap_fowner_denied_over_unmapped_owner() {
    let node = node(5000, 5000);                 // fs owner outside the extents
    let c = cred(0, true);                       // root-ish, holds CAP_FOWNER
    let r = setattr_prepare(&idmapped(), &node, &mut chmod(), &c);
    assert_eq!(r, Err(VfsError::Eperm),
        "CAP_FOWNER cannot chmod an inode whose owner has no mapping in the mount idmap");
}

/// Positive control: same idmap, inode owner fs 1000 maps to vfsuid 0; the
/// caller IS that vfsuid → owner, chmod allowed.
#[test]
fn mapped_owner_allowed() {
    let node = node(1000, 1000);                 // fs 1000 → vfsuid 0
    let c = cred(0, false);                       // owns it as vfsuid 0
    assert!(setattr_prepare(&idmapped(), &node, &mut chmod(), &c).is_ok(),
        "the mapped owner may chmod");
}

/// Positive control: CAP_FOWNER over a MAPPED owner is still allowed (the
/// capability path is denied only on the idmap miss, not in general).
#[test]
fn cap_fowner_allowed_over_mapped_owner() {
    let node = node(1005, 1005);                 // fs 1005 → vfsuid 5 (valid)
    let c = cred(42, true);                        // not the owner, but CAP_FOWNER
    assert!(setattr_prepare(&idmapped(), &node, &mut chmod(), &c).is_ok(),
        "CAP_FOWNER may chmod when the owner is representable in the caller's ns");
}

/// Identity (non-idmapped) mount is unaffected: owner and CAP_FOWNER both pass,
/// a stranger without it is denied — byte-identical to the pre-idmap kernel.
#[test]
fn identity_mount_unchanged() {
    let node = node(1000, 1000);
    let id = Idmap::identity();
    assert!(setattr_prepare(&id, &node, &mut chmod(), &cred(1000, false)).is_ok(), "owner ok");
    assert!(setattr_prepare(&id, &node, &mut chmod(), &cred(7, true)).is_ok(), "CAP_FOWNER ok");
    assert_eq!(setattr_prepare(&id, &node, &mut chmod(), &cred(7, false)), Err(VfsError::Eperm),
        "non-owner without CAP_FOWNER denied");
}
