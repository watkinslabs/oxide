//! Quota usage follows an inode when its owning identity changes.

use super::*;
use super::fixture::*;

use crate::quota::Dqblk;

fn file_with_space(v: &mut Volume<MemImage>) -> u32 {
    let ino = v.create(ROOT_INO, b"f", &spec_of(UID), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; 2 * BLKSIZE]).unwrap();
    ino
}

#[test]
fn chown_moves_existing_space_and_inode_usage_to_the_new_owner() {
    let mut v = with_quota(0, 0, true);
    let ino = file_with_space(&mut v);
    let old = v.quota_record(USRQUOTA, UID).unwrap();
    assert!(old.curspace > 0 && old.curinodes == 1, "the fixture has no usage to move");

    v.set_attr(ino, None, Some((OTHER, OTHER)), NOW).unwrap();

    let from = v.quota_record(USRQUOTA, UID).unwrap();
    let to = v.quota_record(USRQUOTA, OTHER).unwrap();
    assert_eq!(from.curspace, 0, "the former owner still pays for the file's blocks");
    assert_eq!(from.curinodes, 0, "the former owner still pays for the inode");
    assert_eq!(to.curspace, old.curspace, "the new owner was not charged the file's blocks");
    assert_eq!(to.curinodes, old.curinodes, "the new owner was not charged the inode");
}

#[test]
fn chown_is_refused_before_the_inode_changes_when_the_new_owner_has_no_room() {
    let mut v = with_quota(0, 0, true);
    let ino = file_with_space(&mut v);
    let old = v.quota_record(USRQUOTA, UID).unwrap();
    let target = Dqblk { bhardlimit: old.curspace - 1, ..Dqblk::default() };
    v.set_quota_record(USRQUOTA, OTHER, target).unwrap();

    assert_eq!(v.set_attr(ino, None, Some((OTHER, OTHER)), NOW), Err(Errno::Edquot));
    let inode = v.read_inode(ino).unwrap();
    assert_eq!((inode.uid, inode.gid), (UID, UID), "a refused chown changed the inode owner");
    assert_eq!(v.quota_record(USRQUOTA, UID).unwrap(), old,
               "a refused chown removed usage from the old owner");
    assert_eq!(v.quota_record(USRQUOTA, OTHER).unwrap(), target,
               "a refused chown left a partial destination charge");
}
