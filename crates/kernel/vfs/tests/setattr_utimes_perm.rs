//! `setattr_prepare` utimes permission gate (Linux `fs/utimes.c`
//! `utimes_common` + `fs/attr.c` `setattr_prepare`). The `ATTR_TIMES_SET`
//! distinction: setting BOTH atime AND mtime to "now" (NULL `times[]` or both
//! UTIME_NOW) needs only MAY_WRITE (or owner/CAP_FOWNER); ANY other explicit
//! `times[]` — a specific time, OR a per-field selection touching only one of
//! atime/mtime (the other UTIME_OMIT), e.g. `{UTIME_NOW, UTIME_OMIT}` — needs
//! owner/CAP_FOWNER (EPERM). The `utimensat(2)` syscall encodes each slot into
//! `Iattr.valid` exactly as exercised here. Synthetic `Inode`, no FS.

use vfs::setattr::{setattr_prepare, Iattr, ATTR_ATIME, ATTR_MTIME, ATTR_ATIME_SET};
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder};
use vfs::{Cred, FileType, Idmap, InodeRef, KResult, VfsError};

const OWNER_UID: u32 = 1000;
const OWNER_GID: u32 = 1000;

/// Regular-file inode carrying owner uid/gid + perm bits so the DAC class
/// selection in `generic_permission` (owner / group / other) is exercised.
fn time_node(uid: u32, gid: u32, perm: u16) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops())
        .owner(uid, gid).build()
}

/// Cred with an explicit uid, no supplementary groups, no capabilities.
fn cred(uid: u32, gid: u32) -> Cred {
    Cred { uid, gid,
        cap_dac_override: false, cap_dac_read_search: false, cap_fowner: false,
        cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty() }
}

// --- Iattr shapes the utimensat syscall produces for each slot combo ---

/// NULL `times[]` or `{UTIME_NOW, UTIME_NOW}` — both fields, no `*_SET` bit.
fn both_now() -> Iattr { Iattr { valid: ATTR_ATIME | ATTR_MTIME, ..Default::default() } }
/// `{UTIME_NOW, UTIME_OMIT}` — atime to now, mtime untouched (atime only).
fn atime_now_only() -> Iattr { Iattr { valid: ATTR_ATIME, ..Default::default() } }
/// `{UTIME_OMIT, UTIME_NOW}` — mtime to now, atime untouched (mtime only).
fn mtime_now_only() -> Iattr { Iattr { valid: ATTR_MTIME, ..Default::default() } }
/// `{<specific>, UTIME_OMIT}` — a concrete atime (carries `ATTR_ATIME_SET`).
fn atime_specific() -> Iattr { Iattr { valid: ATTR_ATIME | ATTR_ATIME_SET, atime_ns: 12_345, ..Default::default() } }

fn prepare(node: &InodeRef, ia: &mut Iattr, c: &Cred) -> KResult<()> {
    setattr_prepare(&Idmap::identity(), node, ia, c)
}

/// Non-owner WITH write access (file 0o666 → "other" class rw) may set BOTH
/// timestamps to now — the MAY_WRITE path.
#[test]
fn nonowner_writer_both_now_ok() {
    let node = time_node(OWNER_UID, OWNER_GID, 0o666);
    let c = cred(2000, 2000);
    assert_eq!(prepare(&node, &mut both_now(), &c), Ok(()));
}

/// REGRESSION: `{UTIME_NOW, UTIME_OMIT}` (atime-to-now only) is owner-gated even
/// though the live field is "now" — a non-owner with write access is EPERM.
/// Before the fix this took the MAY_WRITE path and wrongly returned Ok.
#[test]
fn nonowner_writer_atime_now_only_eperm() {
    let node = time_node(OWNER_UID, OWNER_GID, 0o666);
    let c = cred(2000, 2000);
    assert_eq!(prepare(&node, &mut atime_now_only(), &c), Err(VfsError::Eperm));
}

/// REGRESSION mirror: `{UTIME_OMIT, UTIME_NOW}` (mtime-to-now only) is likewise
/// owner-gated — non-owner-with-write is EPERM.
#[test]
fn nonowner_writer_mtime_now_only_eperm() {
    let node = time_node(OWNER_UID, OWNER_GID, 0o666);
    let c = cred(2000, 2000);
    assert_eq!(prepare(&node, &mut mtime_now_only(), &c), Err(VfsError::Eperm));
}

/// A specific time always needs ownership — non-owner-with-write is EPERM.
#[test]
fn nonowner_writer_specific_eperm() {
    let node = time_node(OWNER_UID, OWNER_GID, 0o666);
    let c = cred(2000, 2000);
    assert_eq!(prepare(&node, &mut atime_specific(), &c), Err(VfsError::Eperm));
}

/// Non-owner WITHOUT write access (file 0o600) cannot even set both-to-now:
/// the MAY_WRITE check fails with EACCES.
#[test]
fn nonowner_no_write_both_now_eacces() {
    let node = time_node(OWNER_UID, OWNER_GID, 0o600);
    let c = cred(2000, 2000);
    assert_eq!(prepare(&node, &mut both_now(), &c), Err(VfsError::Eacces));
}

/// The owner may set a single field to now (`{UTIME_NOW, UTIME_OMIT}`) — no
/// write bit needed, the ownership branch grants it.
#[test]
fn owner_atime_now_only_ok() {
    let node = time_node(OWNER_UID, OWNER_GID, 0o600);
    let c = cred(OWNER_UID, OWNER_GID);
    assert_eq!(prepare(&node, &mut atime_now_only(), &c), Ok(()));
}

/// The owner may set a specific time (write bit irrelevant).
#[test]
fn owner_specific_ok() {
    let node = time_node(OWNER_UID, OWNER_GID, 0o600);
    let c = cred(OWNER_UID, OWNER_GID);
    assert_eq!(prepare(&node, &mut atime_specific(), &c), Ok(()));
}

/// CAP_FOWNER stands in for ownership: a non-owner holding it may set a specific
/// time on a file it has no write access to.
#[test]
fn cap_fowner_specific_ok() {
    let node = time_node(OWNER_UID, OWNER_GID, 0o600);
    let mut c = cred(2000, 2000);
    c.cap_fowner = true;
    assert_eq!(prepare(&node, &mut atime_specific(), &c), Ok(()));
}
