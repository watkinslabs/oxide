//! `inode_init_owner` (Linux `fs/inode.c`) — owner-id + mode assignment for a
//! NEWLY created inode. Pins the four behaviors the create path depends on:
//! (1) `i_uid` is always the creator's fsuid; (2) the SGID-directory group
//! inheritance rule (`dir & S_ISGID` → inherit dir gid, else fsgid); (3) a new
//! directory under an SGID parent always inherits `S_ISGID`; (4) a new
//! group-executable setgid FILE under an SGID parent keeps `S_ISGID` only for a
//! group-member or CAP_FSETID caller, stripped otherwise. Also pins that umask
//! is the SYSCALL layer's job — `inode_init_owner` takes the already-masked
//! mode AS GIVEN and never re-masks (no double-mask regression).

use vfs::inode::{inode_init_owner, InodeBuilder};
use vfs::types::{S_IFDIR, S_IFREG};
use vfs::{default_file_ops, default_inode_ops, mk_mode, Cred, FileType, InodeRef};

const S_ISGID: u16 = 0o2000;
const S_IXGRP: u16 = 0o0010;

/// Parent directory with an explicit owner gid and permission bits (the
/// `S_ISGID` setgid-directory bit lives in the perm half of `i_mode`).
fn dir(gid: u32, perm: u16) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Directory, perm), default_inode_ops(), default_file_ops())
        .owner(0, gid).build()
}
fn plain_dir(gid: u32) -> InodeRef { dir(gid, 0o755) }
fn sgid_dir(gid: u32) -> InodeRef { dir(gid, 0o2755) }

/// Unprivileged cred (no caps), primary group == `gid`, no supplementary groups.
fn user(uid: u32, gid: u32) -> Cred {
    Cred {
        uid, gid,
        cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty(),
    }
}

// ---- owner ids ----------------------------------------------------------

#[test]
fn uid_is_always_creator_fsuid() {
    // Even under an SGID dir owned by another group, i_uid == caller fsuid.
    let d = sgid_dir(5000);
    let (uid, _gid, _m) = inode_init_owner(&d, S_IFREG | 0o644, &user(1000, 1000));
    assert_eq!(uid, 1000);
}

#[test]
fn gid_is_fsgid_under_plain_dir() {
    // Parent has no S_ISGID → new inode takes the creator's fsgid, NOT dir gid.
    let d = plain_dir(5000);
    let (_uid, gid, _m) = inode_init_owner(&d, S_IFREG | 0o644, &user(1000, 2000));
    assert_eq!(gid, 2000);
}

#[test]
fn gid_inherits_dir_under_sgid_dir() {
    // Parent has S_ISGID → new inode inherits the DIRECTORY's gid (5000),
    // not the caller's fsgid (2000).
    let d = sgid_dir(5000);
    let (_uid, gid, _m) = inode_init_owner(&d, S_IFREG | 0o644, &user(1000, 2000));
    assert_eq!(gid, 5000);
}

// ---- SGID propagation on a new directory --------------------------------

#[test]
fn new_dir_under_sgid_parent_inherits_sgid() {
    // A child directory always gets S_ISGID under an SGID parent, regardless
    // of caller group membership — so the subtree keeps the group.
    let d = sgid_dir(5000);
    let (_u, gid, m) = inode_init_owner(&d, S_IFDIR | 0o755, &user(1000, 2000));
    assert_eq!(gid, 5000);
    assert_ne!(m & S_ISGID, 0, "child dir must inherit S_ISGID");
}

#[test]
fn new_dir_under_plain_parent_has_no_sgid() {
    let d = plain_dir(5000);
    let (_u, _g, m) = inode_init_owner(&d, S_IFDIR | 0o755, &user(1000, 2000));
    assert_eq!(m & S_ISGID, 0);
}

// ---- SGID propagation on a new group-exec setgid file -------------------

#[test]
fn setgid_file_kept_for_group_member() {
    // Caller's fsgid == inherited dir gid (5000): member, so S_ISGID survives.
    let d = sgid_dir(5000);
    let mode = S_IFREG | 0o2755; // setgid + group-exec
    let (_u, gid, m) = inode_init_owner(&d, mode, &user(1000, 5000));
    assert_eq!(gid, 5000);
    assert_ne!(m & S_ISGID, 0, "member keeps the setgid bit");
}

#[test]
fn setgid_file_stripped_for_non_member() {
    // Caller is NOT in the inherited group (5000) and lacks CAP_FSETID → the
    // setgid bit on a group-executable file is STRIPPED (cannot mint a setgid
    // binary running as a group the caller is not in). Group-exec bit stays.
    let d = sgid_dir(5000);
    let mode = S_IFREG | 0o2755;
    let (_u, gid, m) = inode_init_owner(&d, mode, &user(1000, 2000));
    assert_eq!(gid, 5000);
    assert_eq!(m & S_ISGID, 0, "non-member loses the setgid bit");
    assert_ne!(m & S_IXGRP, 0, "group-exec bit is untouched");
}

#[test]
fn setgid_file_kept_via_supplementary_group() {
    // Non-primary but supplementary membership of the dir gid keeps S_ISGID.
    let d = sgid_dir(5000);
    let mut c = user(1000, 2000);
    c.groups = vfs::GroupList::from_slice(&[5000]);
    let (_u, _g, m) = inode_init_owner(&d, S_IFREG | 0o2755, &c);
    assert_ne!(m & S_ISGID, 0);
}

#[test]
fn setgid_file_kept_via_cap_fsetid() {
    // CAP_FSETID lets a non-member keep the setgid bit.
    let d = sgid_dir(5000);
    let mut c = user(1000, 2000);
    c.cap_fsetid = true;
    let (_u, _g, m) = inode_init_owner(&d, S_IFREG | 0o2755, &c);
    assert_ne!(m & S_ISGID, 0);
}

#[test]
fn setgid_no_group_exec_not_stripped() {
    // S_ISGID WITHOUT S_IXGRP is mandatory-locking semantics, not a setgid
    // binary — Linux does NOT strip it for a non-member (the strip predicate
    // requires BOTH bits). Mode 0o2700: setgid, no group-exec.
    let d = sgid_dir(5000);
    let (_u, _g, m) = inode_init_owner(&d, S_IFREG | 0o2700, &user(1000, 2000));
    assert_ne!(m & S_ISGID, 0, "setgid w/o group-exec survives for a non-member");
}

// ---- umask is the caller's job; inode_init_owner never re-masks ----------

#[test]
fn umask_applied_by_caller_not_reapplied() {
    // The syscall layer computes `mode & ~umask` BEFORE calling here. Feeding a
    // pre-masked 0o755 (umask 022 over a 0o777 mkdir) must pass the permission
    // bits through UNCHANGED — inode_init_owner reads no umask of its own.
    let d = plain_dir(5000);
    let masked = S_IFDIR | (0o777 & !0o022); // == S_IFDIR | 0o755
    let (_u, _g, m) = inode_init_owner(&d, masked, &user(1000, 2000));
    assert_eq!(m & 0o7777, 0o755, "permission bits pass through verbatim");
}
