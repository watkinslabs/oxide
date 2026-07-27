//! `may_delete` (Linux `fs/namei.c`) gate: the sticky-dir (`S_ISVTX`)
//! restricted-deletion owner-match, the append-only-parent block, the
//! immutable/append-only victim block, and the isdir type agreement.
//! Synthetic `Inode` impls carrying explicit mode/uid/gid + `i_flags`;
//! `may_delete` is reached via its fully-qualified `vfs::namei` path (the
//! crate root re-export is reported, not edited).

use vfs::inode::{S_APPEND, S_IMMUTABLE};
use vfs::namei::may_delete;
use vfs::{Cred, FileType, InodeBuilder, InodeRef, VfsError, default_file_ops, default_inode_ops, mk_mode};

/// Regular file with explicit perm/uid/gid + VFS `i_flags`.
fn pfile(perm: u16, uid: u32, flags: u32) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops())
        .owner(uid, 0).i_flags(flags).build()
}

/// Directory with explicit perm/uid + VFS `i_flags`.
fn pdir(perm: u16, uid: u32, flags: u32) -> InodeRef {
    InodeBuilder::new(2, mk_mode(FileType::Directory, perm), default_inode_ops(), default_file_ops())
        .owner(uid, 0).i_flags(flags).build()
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

const SVTX: u16 = 0o1000; // S_ISVTX sticky bit (matches vfs::types::S_ISVTX)

// ---- sticky directory restricted deletion --------------------------------

#[test]
fn sticky_non_owner_of_victim_or_dir_denied() {
    // /tmp-style: sticky dir owned by root, victim owned by uid 1000.
    // A different uid (2000) may NOT remove it (Linux check_sticky → EPERM).
    let dir = pdir(0o1777, 0, 0);
    let victim = pfile(0o644, 1000, 0);
    assert_eq!(may_delete(&dir, &victim, false, &user(2000)).err(), Some(VfsError::Eperm),
        "non-owner deletion in a sticky dir is EPERM");
    // Sanity: the dir does carry the sticky bit.
    assert_eq!(dir.perm().unwrap() & SVTX, SVTX);
}

#[test]
fn sticky_victim_owner_allowed() {
    // The victim's owner may remove their own file even in a sticky dir.
    let dir = pdir(0o1777, 0, 0);
    let victim = pfile(0o644, 1000, 0);
    assert!(may_delete(&dir, &victim, false, &user(1000)).is_ok());
}

#[test]
fn sticky_dir_owner_allowed() {
    // The directory's owner may remove any child (owns the dir).
    let dir = pdir(0o1777, 1000, 0);
    let victim = pfile(0o644, 9, 0);
    assert!(may_delete(&dir, &victim, false, &user(1000)).is_ok());
}

#[test]
fn sticky_cap_fowner_allowed() {
    // CAP_FOWNER bypasses the sticky owner-match (capable_wrt_inode_uidgid).
    let dir = pdir(0o1777, 0, 0);
    let victim = pfile(0o644, 1000, 0);
    let mut c = user(2000);
    c.cap_fowner = true;
    assert!(may_delete(&dir, &victim, false, &c).is_ok());
}

#[test]
fn non_sticky_dir_allows_non_owner() {
    // Without the sticky bit, write+exec on the parent is enough — a non-owner
    // may remove the file (the dir is 0o777).
    let dir = pdir(0o777, 0, 0);
    let victim = pfile(0o644, 1000, 0);
    assert!(may_delete(&dir, &victim, false, &user(2000)).is_ok());
}

// ---- parent / victim immutability ----------------------------------------

#[test]
fn append_only_parent_denies_delete() {
    let dir = pdir(0o777, 1000, S_APPEND);
    let victim = pfile(0o644, 1000, 0);
    assert_eq!(may_delete(&dir, &victim, false, &user(1000)).err(), Some(VfsError::Eperm));
}

#[test]
fn immutable_victim_denied() {
    let dir = pdir(0o777, 1000, 0);
    let victim = pfile(0o644, 1000, S_IMMUTABLE);
    assert_eq!(may_delete(&dir, &victim, false, &user(1000)).err(), Some(VfsError::Eperm));
}

#[test]
fn append_only_victim_denied() {
    let dir = pdir(0o777, 1000, 0);
    let victim = pfile(0o644, 1000, S_APPEND);
    assert_eq!(may_delete(&dir, &victim, false, &user(1000)).err(), Some(VfsError::Eperm));
}

// ---- parent permission ----------------------------------------------------

#[test]
fn unwritable_parent_denied() {
    // 0o555 dir (no write); non-owner delete → EACCES (inode_permission).
    let dir = pdir(0o555, 0, 0);
    let victim = pfile(0o644, 2000, 0);
    assert_eq!(may_delete(&dir, &victim, false, &user(2000)).err(), Some(VfsError::Eacces));
}

// ---- isdir type agreement -------------------------------------------------

#[test]
fn rmdir_on_file_is_enotdir() {
    let dir = pdir(0o777, 1000, 0);
    let victim = pfile(0o644, 1000, 0);
    assert_eq!(may_delete(&dir, &victim, true, &user(1000)).err(), Some(VfsError::Enotdir));
}

#[test]
fn unlink_on_dir_is_eisdir() {
    let dir = pdir(0o777, 1000, 0);
    let victim = pdir(0o755, 1000, 0);
    assert_eq!(may_delete(&dir, &victim, false, &user(1000)).err(), Some(VfsError::Eisdir));
}

#[test]
fn rmdir_on_dir_ok() {
    let dir = pdir(0o777, 1000, 0);
    let victim = pdir(0o755, 1000, 0);
    assert!(may_delete(&dir, &victim, true, &user(1000)).is_ok());
}
