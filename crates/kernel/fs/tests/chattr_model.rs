//! `fs::chattr` — the `chmod(2)` / `chown(2)` family work-fns, driven directly
//! against real inodes (Linux `chmod_common` / `chown_common`).
//!
//! Three contracts this pins, all of which the previous shim-resident version
//! got wrong:
//!
//! 1. **`ctime` is stamped.** Both calls carry `ATTR_CTIME`, so a mode or owner
//!    change is observable to every mtime/ctime consumer. The old `iattr`
//!    carried only `ATTR_MODE` / `ATTR_UID|ATTR_GID`, so the inode's timestamps
//!    never moved and `chown(path,-1,-1)` was a total no-op instead of a
//!    ctime bump.
//! 2. **The set-group-ID drop follows `setattr_should_drop_sgid`.** A BARE
//!    S_ISGID (no group-execute — the mandatory-locking mark) survives a chown
//!    by a caller inside the file's group, and drops for one outside it. The
//!    old code set a blanket `ATTR_KILL_SGID` whose apply then re-tested
//!    S_IXGRP, so the mark survived BOTH cases — the outside-the-group leak.
//! 3. **A symlink refuses a mode change with EOPNOTSUPP** wherever the request
//!    enters from.
//!
//! Local inodes, `mnt_id = 0` (no mount, so no EROFS gate); no global state.

use fs::chattr::{chmod_common, chown_common};
use vfs::{default_file_ops, default_inode_ops, mk_mode, Cred, FileType, GroupList, Idmap,
          InodeBuilder, InodeRef, VfsError};

fn file(perm: u16, uid: u32, gid: u32) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops())
        .owner(uid, gid).build()
}

fn dir(perm: u16, uid: u32, gid: u32) -> InodeRef {
    InodeBuilder::new(2, mk_mode(FileType::Directory, perm), default_inode_ops(), default_file_ops())
        .owner(uid, gid).build()
}

fn symlink(uid: u32) -> InodeRef {
    InodeBuilder::new(3, mk_mode(FileType::Symlink, 0o777), default_inode_ops(), default_file_ops())
        .owner(uid, uid).build()
}

fn user(uid: u32, gid: u32, extra: &[u32]) -> Cred {
    Cred { uid, gid, cap_dac_override: false, cap_dac_read_search: false,
           cap_fowner: false, cap_chown: false, cap_fsetid: false,
           groups: GroupList::from_slice(extra) }
}

fn chowner() -> Cred {
    let mut c = user(0, 0, &[]);
    c.cap_chown = true;
    c.cap_fowner = true;
    c
}

const EPERM: Result<(), VfsError> = Err(VfsError::Eperm);
const EOPNOTSUPP: Result<(), VfsError> = Err(VfsError::Eopnotsupp);

/// Fixed wall-clock instant the fake provider reports, so a stamped `ctime`
/// is distinguishable from the as-built zero. # C: O(1)
const FAKE_NOW_NS: u64 = 1_700_000_000_000_000_123;

/// Install the wall-clock provider VFS stamps `ctime` from. The kernel
/// installs the real timekeeper at boot; hosted, none is present and every
/// stamp reads 0, which cannot be told apart from "never stamped".
fn install_clock() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| vfs::inode_times::set_realtime_provider(|| FAKE_NOW_NS));
}

/// The `ctime` a change made at [`FAKE_NOW_NS`] records. # C: O(1)
fn stamped() -> vfs::Timespec64 { vfs::Timespec64::from_clock_ns(FAKE_NOW_NS) }

// A chmod by the owner applies the permission bits and moves ctime off its
// as-built value.
#[test]
fn chmod_applies_mode_and_stamps_ctime() {
    install_clock();
    let f = file(0o644, 1000, 1000);
    assert_eq!(chmod_common(&f, 0, 0o600, &user(1000, 1000, &[])), Ok(()));
    assert_eq!(f.perm(), Some(0o600));
    assert_eq!(f.ctime(), Some(stamped()), "a mode change stamps ctime");
}

// Only the permission half of `mode` is caller-supplied: a chmod cannot retype
// an inode, so the file-type bits are unaffected by whatever the caller passed.
#[test]
fn chmod_cannot_retype_the_inode() {
    let f = file(0o644, 1000, 1000);
    // S_IFDIR in the argument must be ignored, not applied.
    assert_eq!(chmod_common(&f, 0, 0o040_755 as u16, &user(1000, 1000, &[])), Ok(()));
    assert_eq!(f.file_type(), FileType::Regular);
    assert_eq!(f.perm(), Some(0o755));
}

// A symlink has no mode to change; every entry point answers EOPNOTSUPP.
#[test]
fn chmod_on_a_symlink_is_eopnotsupp() {
    let l = symlink(1000);
    assert_eq!(chmod_common(&l, 0, 0o600, &user(1000, 1000, &[])), EOPNOTSUPP);
    assert_eq!(chmod_common(&l, 0, 0o600, &chowner()), EOPNOTSUPP);
}

// A non-owner cannot chmod; the errno is EPERM (not EACCES).
#[test]
fn chmod_by_a_stranger_is_eperm() {
    let f = file(0o666, 1000, 1000);
    assert_eq!(chmod_common(&f, 0, 0o600, &user(2000, 2000, &[])), EPERM);
    assert_eq!(f.perm(), Some(0o666), "a refused chmod changes nothing");
}

// `chown(path, -1, -1)` is not a no-op: it stamps ctime and still runs the
// privilege drop. This is the case the old `valid == 0` iattr silently skipped.
#[test]
fn chown_minus_one_still_stamps_and_drops_privs() {
    install_clock();
    let f = file(0o4755, 1000, 1000);
    assert_eq!(chown_common(&f, 0, None, None, &user(1000, 1000, &[])), Ok(()));
    assert_eq!(f.perm(), Some(0o0755), "set-user-ID drops on any chown of a non-dir");
    assert_eq!(f.ctime(), Some(stamped()), "chown(-1,-1) is a ctime bump, not a no-op");
}

// The set-user-ID bit always dies; a GROUP-EXECUTABLE set-group-ID dies with it.
#[test]
fn chown_drops_suid_and_group_exec_sgid() {
    let f = file(0o6755, 1000, 1000);
    assert_eq!(chown_common(&f, 0, Some(2000), None, &chowner()), Ok(()));
    assert_eq!(f.perm(), Some(0o0755));
    assert_eq!(f.uid(), Some(2000));
}

// A BARE set-group-ID (no group-execute) is the mandatory-locking mark, not a
// privilege bit. `setattr_should_drop_sgid` keeps it when the caller is in the
// file's group and drops it when they are not — the distinction a blanket
// ATTR_KILL_SGID erases.
#[test]
fn bare_sgid_survives_a_chown_from_inside_the_group() {
    let f = file(0o2644, 1000, 500);
    let member = user(1000, 500, &[]);
    assert_eq!(chown_common(&f, 0, Some(1000), None, &member), Ok(()));
    assert_eq!(f.perm(), Some(0o2644), "in-group caller keeps the mandatory-lock mark");

    let g = file(0o2644, 1000, 500);
    // CAP_CHOWN but NOT CAP_FSETID and not in group 500.
    let mut outsider = user(0, 0, &[]);
    outsider.cap_chown = true;
    assert_eq!(chown_common(&g, 0, Some(2000), None, &outsider), Ok(()));
    assert_eq!(g.perm(), Some(0o0644), "an outside caller drops the set-group-ID bit");
}

// A DIRECTORY never drops its privilege bits on chown — `chown_common` guards
// the whole kill mask with `!S_ISDIR`.
#[test]
fn directory_keeps_setid_bits_on_chown() {
    let d = dir(0o6755, 1000, 1000);
    assert_eq!(chown_common(&d, 0, Some(2000), Some(2000), &chowner()), Ok(()));
    assert_eq!(d.perm(), Some(0o6755));
}

// The idmap the drop decision consults is the mount's: on an identity map the
// group test compares raw fs ids, which is what every ordinary mount does.
#[test]
fn sgid_decision_uses_the_mount_idmap() {
    let f = file(0o2644, 1000, 500);
    assert_eq!(vfs::setattr_should_drop_sgid(&Idmap::identity(), f.as_ref(), &user(1000, 500, &[])), 0);
    assert_eq!(vfs::setattr_should_drop_sgid(&Idmap::identity(), f.as_ref(), &user(1000, 9, &[])),
        vfs::ATTR_KILL_SGID);
}
