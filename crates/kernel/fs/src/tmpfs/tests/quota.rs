// tmpfs quota enforcement: the mount's classes and the four `*_hardlimit=`
// ceilings, charged per owner at allocation time.
//
// These drive the charge points directly (no PMM, no frame allocation) so the
// decision — which ceiling refuses, with which errno, in which order — is
// checked without a running kernel.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;

use vfs::fs::{FileSystem, FsFlags, FsType, superblock_from_filesystem};
use vfs::superblock::SuperBlock;
use vfs::{ATTR_GID, ATTR_UID, CreateCtx, Cred, DquotUsage, Iattr, Kqid, QuotaType, VfsError};

use super::super::TmpfsFs;
use super::super::file::TmpfsFileData;
use super::super::limits::PG;
use super::super::quota::{self, QuotaOwner};
use super::super::uapi::TMPFS_MAGIC;

// A live tmpfs superblock built from one mount-option string, with its quota
// classes brought up exactly as `fill_super` does.
fn mounted(data: &str) -> Arc<SuperBlock> {
    let fs = TmpfsFs::from_mount_data(String::from("/"), data).expect("mount opts");
    let root = fs.root_inode();
    let ty = FsType::new("tmpfs", TMPFS_MAGIC, FsFlags::empty(),
        Box::new(|_, _, _, _, _, _| Err(VfsError::Einval)));
    superblock_from_filesystem(ty, fs as Arc<dyn FileSystem>, Some(root), String::from("tmpfs"), 0)
        .expect("realize tmpfs")
}

fn ctx<'a>(cred: &'a Cred) -> CreateCtx<'a> {
    CreateCtx { idmap: &vfs::IDENTITY, cred, umask: 0 }
}

fn user(uid: u32, gid: u32) -> Cred {
    Cred { uid, gid,
        cap_dac_override: true, cap_dac_read_search: true,
        cap_fowner: true, cap_chown: true, cap_fsetid: true,
        groups: vfs::GroupList::empty() }
}

fn usage(sb: &Arc<SuperBlock>, qid: Kqid) -> DquotUsage {
    sb.s_dquot.dquots().lookup(qid).map(|dq| dq.usage()).unwrap_or_default()
}

// The mount's classes come up, and only the ones it asked for.
#[test]
fn only_the_requested_classes_come_up() {
    let sb = mounted("usrquota");
    assert!(sb.s_dquot.is_enabled(QuotaType::User));
    assert!(!sb.s_dquot.is_enabled(QuotaType::Group));
    assert!(sb.s_dquot.is_enforced(QuotaType::User));

    let sb = mounted("quota");
    assert!(sb.s_dquot.is_enabled(QuotaType::User));
    assert!(sb.s_dquot.is_enabled(QuotaType::Group));

    let sb = mounted("size=1m");
    assert!(!sb.s_dquot.is_enabled(QuotaType::User));
    assert!(!sb.s_dquot.is_enabled(QuotaType::Group));
}

// Every created inode is charged to its OWNER, and the mount's inode hard
// limit refuses the one past it with EDQUOT — not ENOSPC, which is what the
// mount-wide ceiling answers with.
#[test]
fn the_inode_hardlimit_refuses_with_edquot() {
    let sb = mounted("usrquota,usrquota_inode_hardlimit=3");
    let root = sb.s_root_inode().expect("root");
    root.set_perm(0o777).expect("perm");
    let cred = user(1000, 1000);

    // The root inode itself is charged to uid 0, not to this user.
    assert_eq!(usage(&sb, Kqid::user(0)).inodes, 1);

    for n in 0..3 {
        root.create_child(&alloc::format!("f{n}"), 0o644, &ctx(&cred)).expect("under limit");
    }
    assert_eq!(usage(&sb, Kqid::user(1000)).inodes, 3);
    assert_eq!(root.create_child("f3", 0o644, &ctx(&cred)).err(), Some(VfsError::Edquot));
    // A refused create leaves nothing charged behind.
    assert_eq!(usage(&sb, Kqid::user(1000)).inodes, 3);

    // Another owner is unaffected by the first one's ceiling.
    let other = user(1001, 1001);
    root.create_child("g0", 0o644, &ctx(&other)).expect("other owner has its own budget");
    assert_eq!(usage(&sb, Kqid::user(1001)).inodes, 1);
}

// Unlinking the last name returns the inode charge to its owner.
#[test]
fn unlink_returns_the_inode_charge() {
    let sb = mounted("usrquota,usrquota_inode_hardlimit=2");
    let root = sb.s_root_inode().expect("root");
    root.set_perm(0o777).expect("perm");
    let cred = user(1000, 1000);

    let f = root.create_child("a", 0o644, &ctx(&cred)).expect("create");
    let g = root.create_child("b", 0o644, &ctx(&cred)).expect("create");
    assert_eq!(root.create_child("c", 0o644, &ctx(&cred)).err(), Some(VfsError::Edquot));
    drop((f, g));
    root.unlink_child("a").expect("unlink");
    assert_eq!(usage(&sb, Kqid::user(1000)).inodes, 1);
    root.create_child("c", 0o644, &ctx(&cred)).expect("budget freed by the unlink");
}

// The group class charges the same inode to the group id, independently.
#[test]
fn the_group_class_charges_the_group_id() {
    let sb = mounted("grpquota,grpquota_inode_hardlimit=1");
    let root = sb.s_root_inode().expect("root");
    root.set_perm(0o777).expect("perm");
    let cred = user(1000, 2000);
    root.create_child("a", 0o644, &ctx(&cred)).expect("create");
    assert_eq!(usage(&sb, Kqid::group(2000)).inodes, 1);
    assert_eq!(root.create_child("b", 0o644, &ctx(&cred)).err(), Some(VfsError::Edquot));
    // The user class was never turned on, so nothing was charged to the uid.
    assert_eq!(usage(&sb, Kqid::user(1000)).inodes, 0);
}

// Block charges are per owner, in bytes, and the mount-wide ceiling is
// consulted BEFORE the quota: a mount that is full answers ENOSPC even for an
// owner well under its own ceiling.
#[test]
fn the_block_ceilings_are_consulted_in_order() {
    let fs = TmpfsFs::from_mount_data(String::from("/"),
        "nr_blocks=4,usrquota,usrquota_block_hardlimit=8192").expect("opts");
    let root = fs.root_inode();
    let ty = FsType::new("tmpfs", TMPFS_MAGIC, FsFlags::empty(),
        Box::new(|_, _, _, _, _, _| Err(VfsError::Einval)));
    let sb = superblock_from_filesystem(ty, fs.clone() as Arc<dyn FileSystem>, Some(root),
        String::from("tmpfs"), 0).expect("realize");
    let acct = fs.accounting();
    let owner = QuotaOwner::new(1000, 1000);

    // Two pages fit the owner's 8 KiB ceiling.
    quota::acct_blocks(&acct, owner, 2).expect("under both ceilings");
    assert_eq!(usage(&sb, Kqid::user(1000)).space, 2 * PG as u64);
    // A third crosses the owner's ceiling while the mount still has room.
    assert_eq!(quota::acct_blocks(&acct, owner, 1), Err(VfsError::Edquot));
    // A refused quota charge returns the mount reservation it took.
    assert_eq!(acct.statfs(TMPFS_MAGIC).f_bfree, 2);

    // A different owner exhausts the MOUNT first, which is ENOSPC.
    let other = QuotaOwner::new(1001, 1001);
    quota::acct_blocks(&acct, other, 2).expect("mount has 2 left");
    assert_eq!(quota::acct_blocks(&acct, other, 1), Err(VfsError::Enospc));
    assert_eq!(usage(&sb, Kqid::user(1001)).space, 2 * PG as u64);

    quota::unacct_blocks(&acct, owner, 2);
    assert_eq!(usage(&sb, Kqid::user(1000)).space, 0);
    assert_eq!(acct.statfs(TMPFS_MAGIC).f_bfree, 2);
}

// An all-or-nothing block reservation: a request the mount cannot satisfy
// takes none of it, so no partial charge is left for the caller to unwind.
#[test]
fn an_oversized_block_request_takes_nothing() {
    let fs = TmpfsFs::from_mount_data(String::from("/"), "nr_blocks=4").expect("opts");
    let acct = fs.accounting();
    assert_eq!(quota::acct_blocks(&acct, QuotaOwner::new(0, 0), 9), Err(VfsError::Enospc));
    assert_eq!(acct.statfs(TMPFS_MAGIC).f_bfree, 4);
}

// A mount with no quota option charges nobody, and its ceilings still refuse
// with ENOSPC.
#[test]
fn a_mount_without_quota_charges_nobody() {
    let sb = mounted("nr_inodes=2");
    let root = sb.s_root_inode().expect("root");
    root.set_perm(0o777).expect("perm");
    let cred = user(1000, 1000);
    root.create_child("a", 0o644, &ctx(&cred)).expect("create");
    assert_eq!(root.create_child("b", 0o644, &ctx(&cred)).err(), Some(VfsError::Enospc));
    assert_eq!(usage(&sb, Kqid::user(1000)).inodes, 0);
}

// A hard limit the mount declares is what a freshly seen id starts with, per
// class, and an id in a class the mount gave no ceiling is unlimited.
#[test]
fn the_declared_ceilings_reach_the_records() {
    let sb = mounted("quota,usrquota_block_hardlimit=1m,grpquota_inode_hardlimit=9");
    let dq = sb.s_dquot.dqget(Kqid::user(7)).expect("user record");
    assert_eq!(dq.limits().space.hard, 1 << 20);
    assert_eq!(dq.limits().inodes.hard, 0, "no inode ceiling was declared for the user class");
    let dq = sb.s_dquot.dqget(Kqid::group(7)).expect("group record");
    assert_eq!(dq.limits().inodes.hard, 9);
    assert_eq!(dq.limits().space.hard, 0);
}

// A chown moves the outstanding charge — both the inode and every data page —
// from the previous owner to the new one, and the body's record of who holds
// the charge moves with it, so the eventual release credits the right owner.
#[test]
fn chown_transfers_the_charge_between_owners() {
    let sb = mounted("quota");
    let root = sb.s_root_inode().expect("root");
    root.set_perm(0o777).expect("perm");
    let cred = user(1000, 1000);
    let f = root.create_child("a", 0o644, &ctx(&cred)).expect("create");
    let d = f.private::<TmpfsFileData>().expect("tmpfs body");
    d.acct_one_block().expect("charge one page");
    d.acct_one_block().expect("charge one page");

    assert_eq!(usage(&sb, Kqid::user(1000)), DquotUsage { space: 2 * PG as u64, reserved_space: 0, inodes: 1 });
    assert_eq!(f.blocks(), 2 * PG as u64 / 512, "i_blocks records what the owner is charged");

    let ia = Iattr { valid: ATTR_UID | ATTR_GID, mode: 0, uid: 1001, gid: 1001,
        size: 0, atime: Default::default(), mtime: Default::default(), ctime: Default::default() };
    f.setattr(&vfs::IDENTITY, &ia).expect("chown");

    assert_eq!(usage(&sb, Kqid::user(1000)), DquotUsage::default(), "previous owner released");
    assert_eq!(usage(&sb, Kqid::user(1001)), DquotUsage { space: 2 * PG as u64, reserved_space: 0, inodes: 1 });
    assert_eq!(usage(&sb, Kqid::group(1001)).space, 2 * PG as u64);

    // The release lands on the owner that now holds the charge.
    d.unacct_blocks(2);
    assert_eq!(usage(&sb, Kqid::user(1001)).space, 0);
    assert_eq!(usage(&sb, Kqid::user(1000)).space, 0);
}

// The block ceiling a chown would exceed refuses the chown, leaving the charge
// where it was.
#[test]
fn a_chown_over_the_new_owner_ceiling_is_refused() {
    let sb = mounted("usrquota,usrquota_block_hardlimit=8192");
    let root = sb.s_root_inode().expect("root");
    root.set_perm(0o777).expect("perm");
    let cred = user(1000, 1000);
    let f = root.create_child("a", 0o644, &ctx(&cred)).expect("create");
    let d = f.private::<TmpfsFileData>().expect("tmpfs body");
    for _ in 0..2 { d.acct_one_block().expect("charge"); }

    // uid 1001 already holds its whole 8 KiB ceiling.
    let g = root.create_child("b", 0o644, &ctx(&user(1001, 1001))).expect("create");
    let dg = g.private::<TmpfsFileData>().expect("tmpfs body");
    for _ in 0..2 { dg.acct_one_block().expect("charge"); }

    let ia = Iattr { valid: ATTR_UID, mode: 0, uid: 1001, gid: 0,
        size: 0, atime: Default::default(), mtime: Default::default(), ctime: Default::default() };
    assert_eq!(f.setattr(&vfs::IDENTITY, &ia), Err(VfsError::Edquot));
    assert_eq!(usage(&sb, Kqid::user(1000)).space, 2 * PG as u64, "charge stayed put");
    assert_eq!(f.uid(), Some(1000), "and so did the owner");
}
