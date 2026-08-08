//! `chown_ok` / `chgrp_ok` — the exact authorization
//! ladder `chown(2)` runs, and the `EOVERFLOW` owner-mapping rule that follows
//! it in `notify_change`.
//!
//! The unprivileged clause is NOT "the requested id equals the current one".
//! It is "the caller IS the owner *and* the requested id equals the current
//! one" — a no-op chown BY the owner. A stranger naming the file's existing
//! uid must be refused, otherwise the ladder leaks a probe: any process could
//! confirm a file's owner by chowning it to a guessed id and reading the
//! errno, and (worse) the same hole let a stranger's `chown(path, owner, -1)`
//! report success where Linux reports EPERM.
//!
//! Fails-before: the gate was `ia.uid != vfsuid && !cap_chown -> EPERM`, i.e.
//! it granted the change whenever the target happened to equal the current
//! owner, whoever asked. `stranger_naming_current_owner_is_refused` and
//! `stranger_naming_current_group_is_refused` fail against that.
//!
//! Local `Inode` + `Cred` + `Idmap`; no global state, no serial guard.

use vfs::{chgrp_ok, chown_ok, check_owner_mappings, setattr_prepare, Iattr};
use vfs::{ATTR_CTIME, ATTR_GID, ATTR_UID};
use vfs::{default_file_ops, default_inode_ops, mk_mode, Cred, FileType, GroupList, Idmap,
          InodeBuilder, InodeRef, VfsError};

/// Regular file owned by fs uid/gid 1000.
fn file(uid: u32, gid: u32) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .owner(uid, gid).build()
}

fn user(uid: u32, gid: u32, extra: &[u32]) -> Cred {
    Cred { uid, gid, cap_dac_override: false, cap_dac_read_search: false,
           cap_fowner: false, cap_chown: false, cap_fsetid: false,
           groups: GroupList::from_slice(extra) }
}

fn chowner(uid: u32) -> Cred {
    let mut c = user(uid, uid, &[]);
    c.cap_chown = true;
    c
}

fn id() -> Idmap { Idmap::identity() }

// The owner may re-assert the id the file already has (Linux's no-op clause).
#[test]
fn owner_may_name_the_current_owner() {
    let f = file(1000, 1000);
    assert!(chown_ok(&id(), &f, 1000, &user(1000, 1000, &[])));
}

// A STRANGER naming the same id is refused — the clause is owner-gated.
#[test]
fn stranger_naming_current_owner_is_refused() {
    let f = file(1000, 1000);
    assert!(!chown_ok(&id(), &f, 1000, &user(2000, 2000, &[])),
        "only the owner may perform the no-op chown");
    // …and the refusal surfaces as EPERM through the real gate.
    let mut ia = Iattr { valid: ATTR_UID | ATTR_CTIME, uid: 1000, ..Default::default() };
    assert_eq!(setattr_prepare(&id(), &f, &mut ia, &user(2000, 2000, &[])), Err(VfsError::Eperm));
}

// Giving a file away is CAP_CHOWN only, even for the owner.
#[test]
fn owner_may_not_give_the_file_away() {
    let f = file(1000, 1000);
    assert!(!chown_ok(&id(), &f, 2000, &user(1000, 1000, &[])));
    assert!(chown_ok(&id(), &f, 2000, &chowner(0)));
}

// chgrp: the owner may move the file into ANY group they belong to, including
// a supplementary one, and may re-assert the current group.
#[test]
fn owner_may_chgrp_within_own_groups() {
    let f = file(1000, 1000);
    let owner = user(1000, 1000, &[4000]);
    assert!(chgrp_ok(&id(), &f, 1000, &owner), "current group");
    assert!(chgrp_ok(&id(), &f, 4000, &owner), "supplementary group");
    assert!(!chgrp_ok(&id(), &f, 5000, &owner), "a group the owner is not in");
}

// A stranger cannot chgrp at all — not even to the group already set, and not
// even to a group they themselves belong to.
#[test]
fn stranger_naming_current_group_is_refused() {
    let f = file(1000, 1000);
    let other = user(2000, 1000, &[1000]);
    assert!(!chgrp_ok(&id(), &f, 1000, &other));
    let mut ia = Iattr { valid: ATTR_GID | ATTR_CTIME, gid: 1000, ..Default::default() };
    assert_eq!(setattr_prepare(&id(), &f, &mut ia, &other), Err(VfsError::Eperm));
}

// Linux checks chown BEFORE chgrp, so a combined request that fails both
// reports the uid's refusal. Both are EPERM here, so the ordering is pinned by
// the case where only the GID is refusable: the uid clause must not consume it.
#[test]
fn combined_uid_gid_reports_the_first_refusal() {
    let f = file(1000, 1000);
    let owner = user(1000, 1000, &[]);
    // uid ok (no-op by owner), gid refused (owner not in group 5000).
    let mut ia = Iattr { valid: ATTR_UID | ATTR_GID | ATTR_CTIME, uid: 1000, gid: 5000, ..Default::default() };
    assert_eq!(setattr_prepare(&id(), &f, &mut ia, &owner), Err(VfsError::Eperm));
}

// `notify_change`'s owner-mapping rule: a target id with no mapping back
// through the mount idmap is EOVERFLOW, and an inode whose EXISTING owner is
// unmapped refuses every change that does not replace that owner.
#[test]
fn unmapped_owner_ids_are_eoverflow() {
    // idmap: fs [0,100) <-> vfs [100000,100100).
    let m = Idmap::uniform(0, 100_000, 100);
    let f = file(50, 50);                       // vfs 100050 — inside the map.
    assert!(check_owner_mappings(&m, &f, 0, 0, 0).is_ok(), "in-map owner, no id change");
    assert_eq!(check_owner_mappings(&m, &f, ATTR_UID, 999_999, 0), Err(VfsError::Eoverflow),
        "target uid outside every extent");
    assert_eq!(check_owner_mappings(&m, &f, ATTR_GID, 0, 999_999), Err(VfsError::Eoverflow),
        "target gid outside every extent");

    let unmapped = file(4000, 4000);            // fs 4000 has no vfs mapping.
    assert_eq!(check_owner_mappings(&m, &unmapped, 0, 0, 0), Err(VfsError::Eoverflow),
        "an inode whose owner is unmapped refuses changes that leave it alone");
    assert!(check_owner_mappings(&m, &unmapped, ATTR_UID | ATTR_GID, 100_001, 100_001).is_ok(),
        "…unless the change makes both ids valid");
}
