//! `may_setattr`, the gate `notify_change` runs BEFORE
//! `setattr_prepare`: an immutable (`chattr +i`) or append-only (`chattr +a`)
//! inode refuses EVERY mode, owner, and explicit-timestamp change with EPERM,
//! and no capability lifts it. The "set both timestamps to now" form is the
//! sole attribute change a non-owner may make, and it still refuses on an
//! immutable inode.
//!
//! Fails-before: `setattr_prepare` had no flag gate at all — the flags were
//! consulted only for an `ATTR_SIZE` change. So `chmod 0777` and `chown` on
//! an immutable file SUCCEEDED for the owner (and for anyone holding
//! CAP_FOWNER / CAP_CHOWN), which is the whole protection `+i` exists to give.
//! Every assertion below fails against that behavior.
//!
//! Local `Inode` + `Cred`; no global state, no serial guard.

use vfs::{may_setattr, setattr_prepare, Iattr};
use vfs::{ATTR_ATIME, ATTR_ATIME_SET, ATTR_CTIME, ATTR_GID, ATTR_MODE, ATTR_MTIME, ATTR_SIZE, ATTR_UID};
use vfs::{default_file_ops, default_inode_ops, mk_mode, Cred, FileType, Idmap, InodeBuilder, InodeRef, VfsError};
use vfs::{S_APPEND, S_IMMUTABLE};

fn inode(flags: u32, perm: u16) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops())
        .owner(1000, 1000).i_flags(flags).build()
}

fn user(uid: u32) -> Cred {
    Cred { uid, gid: uid, cap_dac_override: false, cap_dac_read_search: false,
           cap_fowner: false, cap_chown: false, cap_fsetid: false, groups: vfs::GroupList::empty() }
}

/// Every capability raised — the point being that none of them lift the flags.
fn root() -> Cred {
    Cred { uid: 0, gid: 0, cap_dac_override: true, cap_dac_read_search: true,
           cap_fowner: true, cap_chown: true, cap_fsetid: true, groups: vfs::GroupList::empty() }
}

fn id() -> Idmap { Idmap::identity() }

// chmod on an immutable file is EPERM for the owner AND for a fully
// capable caller.
#[test]
fn immutable_refuses_chmod_even_with_every_capability() {
    let i = inode(S_IMMUTABLE, 0o644);
    for c in [user(1000), root()] {
        let mut ia = Iattr { valid: ATTR_MODE | ATTR_CTIME, mode: 0o777, ..Default::default() };
        assert_eq!(setattr_prepare(&id(), &i, &mut ia, &c), Err(VfsError::Eperm),
            "immutable inode must refuse chmod");
    }
}

// An append-only file is equally closed to a mode change: `+a` guarantees the
// file's content only grows at its end, which a chmod could otherwise unwind.
#[test]
fn append_only_refuses_chmod() {
    let i = inode(S_APPEND, 0o644);
    let mut ia = Iattr { valid: ATTR_MODE | ATTR_CTIME, mode: 0o777, ..Default::default() };
    assert_eq!(setattr_prepare(&id(), &i, &mut ia, &root()), Err(VfsError::Eperm));
}

// chown and chgrp are in the same mask as chmod.
#[test]
fn immutable_and_append_refuse_chown_and_chgrp() {
    for f in [S_IMMUTABLE, S_APPEND] {
        let i = inode(f, 0o644);
        let mut ia = Iattr { valid: ATTR_UID | ATTR_CTIME, uid: 0, ..Default::default() };
        assert_eq!(setattr_prepare(&id(), &i, &mut ia, &root()), Err(VfsError::Eperm), "chown");
        let mut ia = Iattr { valid: ATTR_GID | ATTR_CTIME, gid: 0, ..Default::default() };
        assert_eq!(setattr_prepare(&id(), &i, &mut ia, &root()), Err(VfsError::Eperm), "chgrp");
    }
}

// A SPECIFIC timestamp (`utimensat` with a real instant) is in the mask; the
// "both to now" form is not — but immutable still refuses it, while
// append-only permits it. That asymmetry is exactly Linux's: `may_setattr`
// tests `IS_IMMUTABLE || IS_APPEND` for the explicit form and `IS_IMMUTABLE`
// alone for the touch form.
#[test]
fn timestamp_forms_split_on_the_append_flag() {
    let owner = user(1000);
    let specific = || Iattr { valid: ATTR_ATIME | ATTR_ATIME_SET | ATTR_CTIME, ..Default::default() };
    let touch    = || Iattr { valid: ATTR_ATIME | ATTR_MTIME | ATTR_CTIME, ..Default::default() };

    let imm = inode(S_IMMUTABLE, 0o644);
    assert_eq!(setattr_prepare(&id(), &imm, &mut specific(), &owner), Err(VfsError::Eperm));
    assert_eq!(setattr_prepare(&id(), &imm, &mut touch(), &owner), Err(VfsError::Eperm));

    let app = inode(S_APPEND, 0o644);
    assert_eq!(setattr_prepare(&id(), &app, &mut specific(), &owner), Err(VfsError::Eperm));
    assert!(setattr_prepare(&id(), &app, &mut touch(), &owner).is_ok(),
        "append-only permits `utimes(NULL)`; only immutable closes it");
}

// A plain inode is unaffected — the gate must not become a blanket refusal.
#[test]
fn unflagged_inode_passes_the_gate() {
    let i = inode(0, 0o644);
    for valid in [ATTR_MODE, ATTR_UID, ATTR_GID, ATTR_ATIME | ATTR_MTIME] {
        assert!(may_setattr(&id(), &i, valid, &root()).is_ok(), "valid={valid:#x}");
    }
}

// A SIZE change is deliberately outside both masks (`truncate`'s own append
// reject and MAY_WRITE requirement cover it), so `may_setattr` passes it
// through on an append-only inode and the size-specific reject reports EPERM
// from the next stage. This pins that the two rules stay distinct rather than
// the flag gate swallowing the truncate ladder.
#[test]
fn size_change_is_not_in_the_flag_mask() {
    let app = inode(S_APPEND, 0o644);
    assert!(may_setattr(&id(), &app, ATTR_SIZE, &root()).is_ok());
    let mut ia = Iattr { valid: ATTR_SIZE, size: 0, ..Default::default() };
    assert_eq!(setattr_prepare(&id(), &app, &mut ia, &root()), Err(VfsError::Eperm),
        "the append reject for a size change lives in the size stage");
}
