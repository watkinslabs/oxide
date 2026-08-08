//! The open-time flag rungs of `may_open`, and the order they stand in
//! relative to the access-mode DAC check.
//!
//! Two rungs are covered, both of which a plain access-mode check cannot
//! express:
//!
//! * an APPEND-ONLY inode accepts a write-mode open only in append mode, and
//!   never a truncating one — `EPERM`, decided at open so that a description
//!   which could not legally write is never created;
//! * `O_NOATIME` is an OWNER-ONLY privilege — `EPERM` for anyone who neither
//!   owns the inode nor holds the file-owner capability, because the flag
//!   silently freezes the access time of somebody else's file.
//!
//! Both rungs stand AFTER `inode_permission`, so a caller who is denied by mode
//! bits is told `EACCES` rather than `EPERM` even when the flag rung would also
//! have refused.

use vfs::namei::{may_open, may_open_at, OpenIntent};
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder};
use vfs::{Cred, FileType, InodeRef, VfsError};

/// `S_APPEND` — the inode flag `chattr +a` raises.
const S_APPEND: u32 = vfs::S_APPEND;

fn user(uid: u32, gid: u32) -> Cred {
    Cred {
        uid, gid,
        cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty(),
    }
}

fn file(perm: u16, uid: u32, i_flags: u32) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops())
        .owner(uid, uid).i_flags(i_flags).build()
}

fn chardev(perm: u16, uid: u32, i_flags: u32) -> InodeRef {
    InodeBuilder::new(2, mk_mode(FileType::CharDev, perm), default_inode_ops(), default_file_ops())
        .owner(uid, uid).i_flags(i_flags).build()
}

/// `O_RDONLY`.
fn rd() -> OpenIntent { OpenIntent::default() }
/// `O_WRONLY`.
fn wr() -> OpenIntent { OpenIntent { write_mode: true, ..OpenIntent::default() } }
/// `O_WRONLY | O_APPEND`.
fn wr_append() -> OpenIntent { OpenIntent { write_mode: true, append: true, ..OpenIntent::default() } }

// ---- append-only inode ---------------------------------------------------

#[test]
fn append_only_refuses_a_plain_write_open() {
    let f = file(0o644, 1000, S_APPEND);
    assert_eq!(may_open_at(&f, false, true, wr(), &user(1000, 1000)).err(), Some(VfsError::Eperm),
        "a write-mode open of an append-only inode without O_APPEND is EPERM");
}

#[test]
fn append_only_allows_an_append_write_open() {
    let f = file(0o644, 1000, S_APPEND);
    assert!(may_open_at(&f, false, true, wr_append(), &user(1000, 1000)).is_ok(),
        "O_WRONLY|O_APPEND is exactly what an append-only inode admits");
}

#[test]
fn append_only_allows_a_read_open() {
    let f = file(0o644, 1000, S_APPEND);
    assert!(may_open_at(&f, true, false, rd(), &user(1000, 1000)).is_ok(),
        "the flag bounds writes, not reads");
}

#[test]
fn append_only_refuses_any_truncating_open() {
    let f = file(0o644, 1000, S_APPEND);
    // Even WITH O_APPEND — truncation is refused unconditionally, because the
    // point of the flag is that existing bytes cannot be destroyed.
    let trunc_append = OpenIntent { write_mode: true, append: true, trunc: true, noatime: false };
    assert_eq!(may_open_at(&f, false, true, trunc_append, &user(1000, 1000)).err(), Some(VfsError::Eperm));
    // And on a read-mode open that nonetheless asked to truncate.
    let trunc_only = OpenIntent { trunc: true, ..OpenIntent::default() };
    assert_eq!(may_open_at(&f, true, true, trunc_only, &user(1000, 1000)).err(), Some(VfsError::Eperm));
}

#[test]
fn append_only_binds_the_owner_and_the_privileged_alike() {
    // Not a DAC rung: the flag caps what ANY caller may do, so a cred that
    // overrides file permissions entirely is still refused.
    let f = file(0o666, 1000, S_APPEND);
    assert_eq!(may_open_at(&f, false, true, wr(), &Cred::root()).err(), Some(VfsError::Eperm));
}

#[test]
fn a_plain_inode_is_unaffected_by_the_append_rung() {
    let f = file(0o644, 1000, 0);
    assert!(may_open_at(&f, false, true, wr(), &user(1000, 1000)).is_ok());
    let trunc = OpenIntent { write_mode: true, trunc: true, ..OpenIntent::default() };
    assert!(may_open_at(&f, false, true, trunc, &user(1000, 1000)).is_ok());
}

#[test]
fn a_special_file_drops_the_truncate_request_before_the_append_rung() {
    // An open of a device addresses the driver, not filesystem data, so the
    // truncate request is dropped and cannot trip the append-only rung.
    let d = chardev(0o666, 1000, S_APPEND);
    let trunc = OpenIntent { trunc: true, ..OpenIntent::default() };
    assert!(may_open_at(&d, true, false, trunc, &user(1000, 1000)).is_ok());
}

// ---- O_NOATIME -----------------------------------------------------------

/// `O_RDONLY | O_NOATIME`.
fn rd_noatime() -> OpenIntent { OpenIntent { noatime: true, ..OpenIntent::default() } }

#[test]
fn noatime_by_a_stranger_is_eperm() {
    // World-readable file owned by uid 1000; uid 2000 may READ it, and that is
    // exactly why the rung matters — the DAC check passes and the open must
    // still be refused.
    let f = file(0o644, 1000, 0);
    assert_eq!(may_open_at(&f, true, false, rd_noatime(), &user(2000, 2000)).err(), Some(VfsError::Eperm),
        "O_NOATIME on another user's file must not silently succeed");
}

#[test]
fn noatime_by_the_owner_is_allowed() {
    let f = file(0o644, 1000, 0);
    assert!(may_open_at(&f, true, false, rd_noatime(), &user(1000, 1000)).is_ok());
}

#[test]
fn noatime_with_the_file_owner_capability_is_allowed() {
    let f = file(0o644, 1000, 0);
    let mut c = user(2000, 2000);
    c.cap_fowner = true;
    assert!(may_open_at(&f, true, false, rd_noatime(), &c).is_ok());
}

#[test]
fn noatime_without_the_flag_is_allowed_for_anyone() {
    let f = file(0o644, 1000, 0);
    assert!(may_open_at(&f, true, false, rd(), &user(2000, 2000)).is_ok());
}

// ---- rung ORDER ----------------------------------------------------------

#[test]
fn the_access_mode_denial_outranks_both_flag_rungs() {
    // 0o600 owned by uid 1000: uid 2000 cannot read it at all. Asking for
    // O_NOATIME as well must still report the ACCESS failure, not the
    // ownership one — the flag rungs run after `inode_permission`.
    let f = file(0o600, 1000, S_APPEND);
    assert_eq!(may_open_at(&f, true, false, rd_noatime(), &user(2000, 2000)).err(), Some(VfsError::Eacces));
    // Same for the append rung: a write the caller may not perform at all is
    // EACCES, never the append-only EPERM.
    assert_eq!(may_open_at(&f, false, true, wr(), &user(2000, 2000)).err(), Some(VfsError::Eacces));
}

#[test]
fn the_file_type_verdict_outranks_the_flag_rungs() {
    // A trailing symlink left unfollowed is ELOOP before anything else runs.
    let l = InodeBuilder::new(3, mk_mode(FileType::Symlink, 0o777), default_inode_ops(),
        default_file_ops()).owner(1000, 1000).i_flags(S_APPEND).build();
    assert_eq!(may_open_at(&l, false, true, wr(), &user(2000, 2000)).err(), Some(VfsError::Eloop));
}

#[test]
fn the_flag_rungs_still_run_when_no_access_is_requested() {
    // An open that carries no access-mode mask (a just-created file) is still
    // subject to the flag-decided rungs — they are decided by the FLAGS.
    let f = file(0o644, 1000, 0);
    assert_eq!(may_open_at(&f, false, false, rd_noatime(), &user(2000, 2000)).err(), Some(VfsError::Eperm));
}

// ---- the flag-less form --------------------------------------------------

#[test]
fn the_flagless_form_declares_no_flags_and_trips_no_flag_rung() {
    let f = file(0o644, 1000, S_APPEND);
    // No O_APPEND is declared, but neither is a write MODE, so nothing trips.
    assert!(may_open(&f, true, false, &user(1000, 1000)).is_ok());
    assert!(may_open(&f, false, true, &user(1000, 1000)).is_ok(),
        "the flag-less caller declares no access MODE, so the append rung stays quiet");
}
