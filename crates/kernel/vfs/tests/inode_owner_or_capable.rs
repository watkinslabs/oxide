//! `inode_owner_or_capable` (Linux `fs/inode.c`) — the canonical
//! owner-or-`CAP_FOWNER` predicate chmod / specific-time-utimes / chattr /
//! `setattr_prepare` reduce to. Before this helper the test lived only inline as
//! `cred.uid == vfsuid || cred.cap_fowner` (setattr_prepare / may_chmod), which
//! has TWO consolidation gaps these tests pin: (1) the inode `i_uid` must be
//! mapped THROUGH the mount idmap (compare against the file's *vfsuid*, not the
//! raw on-disk id); (2) `CAP_FOWNER` must NOT grant when the owner is unmapped
//! in the caller's id space (Linux `vfsuid_has_mapping`) — an idmap miss
//! (`INVALID_ID`) denies the capability path. The inline form silently grants
//! that case; this helper denies it.

use vfs::idmap::Idmap;
use vfs::inode::{inode_owner_or_capable, InodeBuilder};
use vfs::{default_file_ops, default_inode_ops, mk_mode, Cred, FileType, InodeRef};

/// Regular file with an explicit on-disk owner uid.
fn ofile(uid: u32) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .owner(uid, uid).build()
}

/// Unprivileged cred (no caps).
fn user(uid: u32) -> Cred {
    Cred {
        uid, gid: uid,
        cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty(),
    }
}
/// Cred holding CAP_FOWNER but NOT owning the file.
fn fowner(uid: u32) -> Cred { let mut c = user(uid); c.cap_fowner = true; c }

// ---- identity (non-idmapped) mount --------------------------------------

#[test]
fn owner_matches_regardless_of_caps() {
    // fsuid == file vfsuid → true even with zero capabilities.
    let f = ofile(1000);
    assert!(inode_owner_or_capable(&Idmap::identity(), &f, &user(1000)));
}

#[test]
fn non_owner_without_cap_denied() {
    let f = ofile(1000);
    assert!(!inode_owner_or_capable(&Idmap::identity(), &f, &user(2000)));
}

#[test]
fn non_owner_with_cap_fowner_allowed() {
    // CAP_FOWNER bypasses the owner check on an identity mount (owner is mapped).
    let f = ofile(1000);
    assert!(inode_owner_or_capable(&Idmap::identity(), &f, &fowner(2000)));
}

// ---- idmapped mount: compare against vfsuid, not raw fs uid --------------

#[test]
fn idmapped_owner_uses_mapped_vfsuid() {
    // Mount maps fs ids [1000,+10) <-> vfs ids [100000,+10). File fs uid 1000 →
    // vfsuid 100000. The owner is the caller whose fsuid is the MAPPED 100000.
    let map = Idmap::uniform(1000, 100_000, 10);
    let f = ofile(1000);
    assert!(inode_owner_or_capable(&map, &f, &user(100_000)));
}

#[test]
fn idmapped_raw_fs_uid_is_not_owner() {
    // A caller whose fsuid equals the RAW on-disk id (1000) is NOT the owner on
    // an idmapped mount — proves the predicate maps before comparing.
    let map = Idmap::uniform(1000, 100_000, 10);
    let f = ofile(1000);
    assert!(!inode_owner_or_capable(&map, &f, &user(1000)));
}

#[test]
fn idmap_miss_denies_cap_fowner() {
    // File fs uid 5000 falls outside the mount's only extent [1000,+10), so the
    // owner has no mapping in the caller's id space (vfsuid == INVALID_ID).
    // Linux `vfsuid_has_mapping` fails → CAP_FOWNER does NOT grant. The old
    // inline `cred.uid == vfsuid || cred.cap_fowner` would have granted here.
    let map = Idmap::uniform(1000, 100_000, 10);
    let f = ofile(5000);
    assert!(!inode_owner_or_capable(&map, &f, &fowner(7000)));
}
