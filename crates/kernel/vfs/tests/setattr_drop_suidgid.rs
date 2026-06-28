//! Write-path privilege drop (`setattr_should_drop_suidgid`, Linux `fs/attr.c`):
//! a modifying write strips S_ISUID always and S_ISGID when group-executable,
//! unless the writer holds CAP_FSETID; non-regular inodes are never touched.
//! Synthetic `Inode` impls carrying explicit POSIX mode — no real filesystem.

use vfs::inode::Inode;
use vfs::{Cred, FileType, InodeRef, VfsError, CRED_NGROUPS};
use vfs::setattr::{setattr_should_drop_suidgid, ATTR_KILL_SUID, ATTR_KILL_SGID};

/// Inode of `ft` with explicit perm bits (including setid bits in low-12).
struct PNode { perm: u16, ft: FileType }
impl Inode for PNode {
    fn ino(&self) -> vfs::Ino { 1 }
    fn file_type(&self) -> FileType { self.ft }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> vfs::KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn perm(&self) -> Option<u16> { Some(self.perm) }
    fn uid(&self) -> Option<u32> { Some(0) }
    fn gid(&self) -> Option<u32> { Some(0) }
}
fn reg(perm: u16) -> PNode { PNode { perm, ft: FileType::Regular } }
fn dir(perm: u16) -> PNode { PNode { perm, ft: FileType::Directory } }

/// Unprivileged cred (no CAP_FSETID).
fn user() -> Cred {
    Cred {
        uid: 1000, gid: 1000,
        cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        ngroups: 0, groups: [0u32; CRED_NGROUPS],
    }
}

#[test]
fn suid_regular_unprivileged_killed() {
    // 0o4755 regular file, unprivileged write → S_ISUID killed.
    assert_eq!(setattr_should_drop_suidgid(&reg(0o4755), &user()), ATTR_KILL_SUID);
}

#[test]
fn sgid_group_exec_killed_with_suid() {
    // 0o6755 (suid+sgid+group-exec) → both kill flags set.
    assert_eq!(
        setattr_should_drop_suidgid(&reg(0o6755), &user()),
        ATTR_KILL_SUID | ATTR_KILL_SGID,
    );
}

#[test]
fn bare_sgid_no_group_exec_preserved() {
    // 0o2644: sgid set but NOT group-executable = mandatory-lock mark → not killed.
    assert_eq!(setattr_should_drop_suidgid(&reg(0o2644), &user()), 0);
}

#[test]
fn sgid_with_group_exec_alone_killed() {
    // 0o2755: sgid + group-exec, no suid → only ATTR_KILL_SGID.
    assert_eq!(setattr_should_drop_suidgid(&reg(0o2755), &user()), ATTR_KILL_SGID);
}

#[test]
fn cap_fsetid_holder_keeps_bits() {
    // CAP_FSETID writer keeps the setid bits.
    let mut c = user();
    c.cap_fsetid = true;
    assert_eq!(setattr_should_drop_suidgid(&reg(0o6755), &c), 0);
}

#[test]
fn directory_suid_never_dropped() {
    // setid on a directory is meaningful; the write-path drop is regular-only.
    assert_eq!(setattr_should_drop_suidgid(&dir(0o6755), &user()), 0);
}

#[test]
fn plain_regular_no_setid_zero() {
    assert_eq!(setattr_should_drop_suidgid(&reg(0o0644), &user()), 0);
}
