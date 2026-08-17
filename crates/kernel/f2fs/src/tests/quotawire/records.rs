//! Identities the quota file has never held, and files the mount names.

use super::*;
use super::fixture::*;

// --------------------------------------------- identities the file never held

#[test]
fn a_first_allocation_by_an_identity_the_file_has_never_held_is_recorded() {
    // The planted tree has a slot for one identity and none for anybody else.
    // Until the checkpoint could GROW the tree, every other identity's
    // accounting was written nowhere and vanished at the next mount — which
    // is every uid, gid and project the volume ever meets for the first time.
    let mut v = with_quota(0, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec_of(OTHER), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; 2 * BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    let want = v.quota_record(USRQUOTA, OTHER).unwrap();
    assert!(want.curspace > 0 && want.curinodes == 1);
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let mut o = Options::defaults();
    o.usrquota = true;
    let mut v =
        Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), o, true).unwrap();
    v.set_clock(NOW.0);
    assert_eq!(
        v.quota_record(USRQUOTA, OTHER).unwrap(),
        want,
        "a new identity's accounting did not reach the medium",
    );
}

#[test]
fn a_record_with_nothing_left_in_it_is_removed_rather_than_kept() {
    // A file that only ever grows keeps a slot for every identity that ever
    // allocated a byte, so a record whose usage is gone and whose limits are
    // unset is taken out.
    let mut v = with_quota(0, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec_of(OTHER), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.commit().unwrap();
    assert_eq!(
        v.quota_next_record(USRQUOTA, OTHER).unwrap().map(|(id, _)| id),
        Some(OTHER),
        "the identity was not recorded in the first place",
    );
    v.remove(ROOT_INO, b"f", false, NOW).unwrap();
    // The name going parks the inode; the EVICTION is what frees it and
    // gives back what it held. The two are separate events, and a descriptor
    // may sit between them.
    v.evict_inode(ino).unwrap();
    v.commit().unwrap();
    assert_eq!(v.quota_next_record(USRQUOTA, OTHER).unwrap(), None);
    // Everything else the file held is still there.
    assert!(v.quota_next_record(USRQUOTA, 0).unwrap().is_some());
}

#[test]
fn the_next_identity_scan_answers_off_the_file_and_stops_at_the_end() {
    let mut v = with_quota(0, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec_of(OTHER), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.commit().unwrap();
    let first = v.quota_next_record(USRQUOTA, 0).unwrap().expect("an identity");
    assert_eq!(first.0, UID.min(OTHER));
    let next = v.quota_next_record(USRQUOTA, first.0 + 1).unwrap().expect("the other");
    assert_eq!(next.0, UID.max(OTHER));
    assert_eq!(v.quota_next_record(USRQUOTA, next.0 + 1).unwrap(), None);
    // A kind this volume does not account has no next identity at all, which
    // is how a caller tells that apart from a file with no records.
    assert_eq!(v.quota_next_record(GRPQUOTA, 0), Err(Errno::Esrch));
}

// ------------------------------------------------ files the mount names

#[test]
fn a_quota_file_the_mount_named_is_looked_up_and_accounted_against() {
    use crate::opts::jquota::{JqFmt, QKind, QfName};

    // No quota inodes at all: the mount line is the only thing that can point
    // at a quota file, and the file is an ordinary entry in the root.
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.set_clock(NOW.0);
    let qino = v.create(ROOT_INO, b"aquota.user", &spec_of(UID), None).unwrap();
    v.write_file(qino, 0, &qi::user_file(UID, 0, 0)).unwrap();
    v.sync_data().unwrap();
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();

    let mut o = Options::defaults();
    o.jquota.names[QKind::User as usize] = Some(QfName::new("aquota.user").unwrap());
    o.jquota.fmt = Some(JqFmt::VfsV1);
    let mut v =
        Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), o, true).unwrap();
    v.set_clock(NOW.0);
    assert!(v.quota_active(), "the kind the mount named is not accounted");
    assert_eq!(v.quota_setup()[USRQUOTA].ino, qino, "the name reached no inode");

    let ino = v.create(ROOT_INO, b"f", &spec_of(UID), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    assert!(space(&mut v) > 0, "nothing was charged against the named file");

    // The named file is owned by the very identity it accounts. Charging its
    // own blocks to that identity is a loop with no end.
    let before = space(&mut v);
    v.commit().unwrap();
    assert_eq!(space(&mut v), before, "the named quota file charged its own owner");
}

#[test]
fn a_named_quota_file_that_is_not_there_leaves_the_kind_unaccounted() {
    use crate::opts::jquota::{JqFmt, QKind, QfName};

    let v = test_image::with_root().mount_rw().unwrap();
    let bytes = v.into_source().snapshot();
    let mut o = Options::defaults();
    o.jquota.names[QKind::User as usize] = Some(QfName::new("aquota.user").unwrap());
    o.jquota.fmt = Some(JqFmt::VfsV1);
    // Refusing the mount would leave nobody able to put the file there.
    let v = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), o, true).unwrap();
    assert!(!v.quota_active());
    assert_eq!(v.quota_setup()[USRQUOTA].ino, 0);
}
