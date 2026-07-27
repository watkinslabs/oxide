//! Chown/`setattr_copy`-path S_ISGID strip (`setattr_should_drop_sgid`, Linux
//! `fs/attr.c`): a setgid file drops S_ISGID when it is group-executable, OR
//! when the caller is neither in the inode's *vfsgid* group nor CAP_FSETID —
//! the `in_group_or_capable` edge that prevents a setgid bit leaking to a
//! process outside the file's group. The inode gid is mapped through the mount
//! idmap before the group comparison, so an idmapped mount tests the vfsgid.
//! Synthetic `Inode`s carrying explicit POSIX mode + gid — no real fs.

use vfs::idmap::Idmap;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder};
use vfs::{Cred, FileType, InodeRef};
use vfs::setattr::{setattr_should_drop_sgid, ATTR_KILL_SGID};

/// Regular-file inode with explicit perm bits and group id.
fn node(perm: u16, gid: u32) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops())
        .owner(0, gid).build()
}

/// Unprivileged cred with fsgid `gid` and no supplementary groups, no caps.
fn user(gid: u32) -> Cred {
    Cred {
        uid: 1000, gid,
        cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty(),
    }
}

#[test]
fn no_sgid_returns_zero() {
    // Plain 0o0644 file — nothing to strip.
    assert_eq!(setattr_should_drop_sgid(&Idmap::identity(), &node(0o0644, 0), &user(1000)), 0);
}

#[test]
fn group_exec_sgid_always_killed() {
    // 0o2755: setgid + group-exec → killed regardless of group membership.
    assert_eq!(
        setattr_should_drop_sgid(&Idmap::identity(), &node(0o2755, 0), &user(1000)),
        ATTR_KILL_SGID,
    );
    // Even when the caller IS in the group, group-exec setgid still drops.
    assert_eq!(
        setattr_should_drop_sgid(&Idmap::identity(), &node(0o2755, 1000), &user(1000)),
        ATTR_KILL_SGID,
    );
}

#[test]
fn bare_sgid_non_member_killed() {
    // 0o2644: bare setgid, caller's fsgid (1000) != file gid (0), no groups,
    // no CAP_FSETID → not in_group_or_capable → dropped.
    assert_eq!(
        setattr_should_drop_sgid(&Idmap::identity(), &node(0o2644, 0), &user(1000)),
        ATTR_KILL_SGID,
    );
}

#[test]
fn bare_sgid_member_preserved() {
    // Caller's fsgid matches the file gid → in_group → setgid kept.
    assert_eq!(setattr_should_drop_sgid(&Idmap::identity(), &node(0o2644, 1000), &user(1000)), 0);
}

#[test]
fn bare_sgid_supplementary_group_preserved() {
    // File gid in the caller's supplementary groups → in_group → kept.
    let mut c = user(42);
    c.groups = vfs::GroupList::from_slice(&[1000]);
    assert_eq!(setattr_should_drop_sgid(&Idmap::identity(), &node(0o2644, 1000), &c), 0);
}

#[test]
fn bare_sgid_cap_fsetid_preserved() {
    // CAP_FSETID holder keeps the bit even as a non-member.
    let mut c = user(1000);
    c.cap_fsetid = true;
    assert_eq!(setattr_should_drop_sgid(&Idmap::identity(), &node(0o2644, 0), &c), 0);
}

#[test]
fn idmapped_vfsgid_member_preserved() {
    // Mount idmap fs[0..1000) <-> vfs[10000..11000). File fs-gid 5 → vfsgid
    // 10005; a caller whose fsgid is the VFSGID 10005 is "in group" → kept.
    let m = Idmap::uniform(0, 10_000, 1000);
    assert_eq!(setattr_should_drop_sgid(&m, &node(0o2644, 5), &user(10_005)), 0);
    // A caller matching the RAW fs-gid (5) is NOT the vfsgid → dropped.
    assert_eq!(setattr_should_drop_sgid(&m, &node(0o2644, 5), &user(5)), ATTR_KILL_SGID);
}
