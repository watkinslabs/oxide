//! D4 permission-enforcement tests for the pure VFS decision functions
//! (`inode_permission`, `may_open`, `may_create`, `may_chmod`, `may_chown`,
//! `chmod_sgid_strip`, `chown_kill_priv`). Synthetic `Inode` impls carrying
//! explicit POSIX mode/uid/gid — no real filesystem, no `sched`.

use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder};
use vfs::{Cred, FileType, InodeRef, VfsError};
use vfs::{inode_permission, may_open, may_create, may_chmod, may_chown,
    chmod_sgid_strip, chown_kill_priv, MAY_EXEC, MAY_READ, MAY_WRITE};

/// Regular file with explicit perm/uid/gid (default ops — only the permission
/// decision functions are exercised, never `lookup`).
fn pfile(perm: u16, uid: u32, gid: u32) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops())
        .owner(uid, gid).build()
}

/// Directory with explicit perm/uid/gid (default ops).
fn pdir(perm: u16, uid: u32, gid: u32) -> InodeRef {
    InodeBuilder::new(2, mk_mode(FileType::Directory, perm), default_inode_ops(), default_file_ops())
        .owner(uid, gid).build()
}

/// Unprivileged cred (no caps); `groups` empty unless specified.
fn user(uid: u32, gid: u32) -> Cred {
    Cred {
        uid, gid,
        cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty(),
    }
}

// ---- may_open ------------------------------------------------------------

#[test]
fn open_rdonly_no_read_bit_denied() {
    // 0o000 file owned by uid 0; non-owner opening O_RDONLY → EACCES.
    let f = pfile(0o000, 0, 0);
    assert_eq!(may_open(&f, true, false, &user(1000, 1000)).err(), Some(VfsError::Eacces));
}

#[test]
fn open_rdonly_owner_with_read_ok() {
    // 0o600 owned by uid 1000; owner reads → ok.
    let f = pfile(0o600, 1000, 1000);
    assert!(may_open(&f, true, false, &user(1000, 1000)).is_ok());
}

#[test]
fn open_wronly_readonly_file_non_owner_denied() {
    // 0o444 (no write for anyone); non-owner O_WRONLY → EACCES.
    let f = pfile(0o444, 0, 0);
    assert_eq!(may_open(&f, false, true, &user(1000, 1000)).err(), Some(VfsError::Eacces));
}

#[test]
fn open_write_directory_is_eisdir() {
    let d = pdir(0o777, 1000, 1000);
    assert_eq!(may_open(&d, false, true, &user(1000, 1000)).err(), Some(VfsError::Eisdir));
}

#[test]
fn root_bypasses_open_via_cap_dac_override() {
    // 0o000 file; root cred (CAP_DAC_OVERRIDE) reads it.
    let f = pfile(0o000, 0, 0);
    assert!(may_open(&f, true, false, &Cred::root()).is_ok());
}

// ---- may_create ----------------------------------------------------------

#[test]
fn create_in_unwritable_dir_denied() {
    // 0o555 dir (no write); non-owner create → EACCES.
    let d = pdir(0o555, 0, 0);
    assert_eq!(may_create(&d, &user(1000, 1000)).err(), Some(VfsError::Eacces));
}

#[test]
fn create_in_writable_dir_ok() {
    let d = pdir(0o755, 1000, 1000);
    assert!(may_create(&d, &user(1000, 1000)).is_ok());
}

// ---- inode_permission X_OK ----------------------------------------------

#[test]
fn access_x_ok_non_exec_denied() {
    // 0o644 (no exec) file; X_OK → EACCES even though CAP-less owner.
    let f = pfile(0o644, 1000, 1000);
    assert_eq!(inode_permission(&f, MAY_EXEC, &user(1000, 1000)).err(), Some(VfsError::Eacces));
}

#[test]
fn access_x_ok_exec_ok() {
    let f = pfile(0o755, 1000, 1000);
    assert!(inode_permission(&f, MAY_EXEC, &user(1000, 1000)).is_ok());
}

#[test]
fn cap_dac_override_does_not_grant_exec_without_any_x_bit() {
    // Linux: CAP_DAC_OVERRIDE grants exec on a non-dir only if some x bit set.
    let f = pfile(0o644, 0, 0);
    let mut c = user(0, 0);
    c.cap_dac_override = true;
    assert_eq!(inode_permission(&f, MAY_EXEC, &c).err(), Some(VfsError::Eacces));
}

// ---- supplementary groups ------------------------------------------------

#[test]
fn supplementary_group_grants_group_access() {
    // File group 50, rw for group; user primary gid 1000 but supplementary 50.
    let f = pfile(0o060, 0, 50);
    let mut c = user(1000, 1000);
    c.groups = vfs::GroupList::from_slice(&[50]);
    assert!(inode_permission(&f, MAY_READ | MAY_WRITE, &c).is_ok());
    // A user NOT in group 50 is denied (other class = 0).
    assert_eq!(inode_permission(&f, MAY_READ, &user(1000, 1000)).err(), Some(VfsError::Eacces));
}

// ---- may_chmod -----------------------------------------------------------

#[test]
fn chmod_non_owner_denied() {
    let f = pfile(0o644, 0, 0);
    assert_eq!(may_chmod(&f, &user(1000, 1000)).err(), Some(VfsError::Eperm));
}

#[test]
fn chmod_owner_ok() {
    let f = pfile(0o644, 1000, 1000);
    assert!(may_chmod(&f, &user(1000, 1000)).is_ok());
}

#[test]
fn chmod_cap_fowner_ok() {
    let f = pfile(0o644, 0, 0);
    let mut c = user(1000, 1000);
    c.cap_fowner = true;
    assert!(may_chmod(&f, &c).is_ok());
}

// ---- may_chown -----------------------------------------------------------

#[test]
fn chown_uid_change_without_cap_denied() {
    let f = pfile(0o644, 1000, 1000);
    // owner tries to give the file to uid 0 without CAP_CHOWN → EPERM.
    assert_eq!(may_chown(&f, Some(0), None, &user(1000, 1000)).err(), Some(VfsError::Eperm));
}

#[test]
fn chown_uid_change_with_cap_ok() {
    let f = pfile(0o644, 1000, 1000);
    let mut c = user(1000, 1000);
    c.cap_chown = true;
    assert!(may_chown(&f, Some(0), None, &c).is_ok());
}

#[test]
fn chown_noop_uid_minus_one_ok() {
    // (uid_t)-1 → None → no uid change → allowed even without CAP_CHOWN.
    let f = pfile(0o644, 1000, 1000);
    assert!(may_chown(&f, None, None, &user(1000, 1000)).is_ok());
}

#[test]
fn chown_gid_to_member_group_by_owner_ok() {
    let f = pfile(0o644, 1000, 1000);
    let mut c = user(1000, 1000);
    c.groups = vfs::GroupList::from_slice(&[50]);
    assert!(may_chown(&f, None, Some(50), &c).is_ok());
}

#[test]
fn chown_gid_to_nonmember_group_denied() {
    let f = pfile(0o644, 1000, 1000);
    assert_eq!(may_chown(&f, None, Some(50), &user(1000, 1000)).err(), Some(VfsError::Eperm));
}

// ---- suid/sgid stripping -------------------------------------------------

#[test]
fn chmod_strips_sgid_for_nonmember() {
    // setting 0o2755 on a file in group 50 by a non-member non-FSETID → sgid cleared.
    let f = pfile(0o644, 1000, 50);
    let stripped = chmod_sgid_strip(0o2755, &f, &user(1000, 1000));
    assert_eq!(stripped, 0o0755);
}

#[test]
fn chmod_keeps_sgid_for_member() {
    let f = pfile(0o644, 1000, 50);
    let mut c = user(1000, 1000);
    c.groups = vfs::GroupList::from_slice(&[50]);
    assert_eq!(chmod_sgid_strip(0o2755, &f, &c), 0o2755);
}

#[test]
fn chown_kills_suid_and_group_exec_sgid() {
    // 0o6755 (suid+sgid+rwxr-xr-x) on a regular file → suid+sgid dropped.
    assert_eq!(chown_kill_priv(0o6755, false), Some(0o0755));
    // sgid without group-exec is preserved (only suid dropped).
    assert_eq!(chown_kill_priv(0o4644, false), Some(0o0644));
    // directories are untouched.
    assert_eq!(chown_kill_priv(0o6755, true), None);
    // nothing to strip → None.
    assert_eq!(chown_kill_priv(0o0644, false), None);
}
