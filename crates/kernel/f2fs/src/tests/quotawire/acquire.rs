//! Every operation that can allocate acquires its records BEFORE it starts.
//!
//! This is the file that can fail when an entry point loses its acquisition,
//! and the tests elsewhere in this directory cannot. They build their file on
//! the same mount that then operates on it, so the `create` has already brought
//! the identity's record in and attached it — removing the acquisition from any
//! later entry point leaves them all passing. What separates the two is a
//! volume nothing has been acquired on yet, which is what every FRESH MOUNT is:
//! the records and the attachments live with the mount, so a remount is the
//! state a first operation actually meets.
//!
//! The assertion is that the record is HELD afterwards, not that usage moved.
//! Some of these operations charge nothing on their own — a rename that finds
//! room in an existing directory block, an exchange that rewrites two entries
//! in place — and a test that looked at the counts would pass on them for the
//! wrong reason. Holding the record is what the entry point is responsible for;
//! whether the charge then comes to anything is the operation's business.

use super::*;
use super::fixture::*;
use crate::volume::rename::Rename;

/// The fixture's volume, written to, put down and picked up again — so nothing
/// is acquired and nothing is attached, exactly as on a first operation.
fn remounted() -> (Volume<MemImage>, u32) {
    let mut v = with_quota(0, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.create(ROOT_INO, b"g", &spec(), None).unwrap();
    v.sync_data().unwrap();
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let mut o = Options::defaults();
    o.usrquota = true;
    let mut v = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), o, true).unwrap();
    v.set_clock(NOW.0);
    assert!(!v.dquot_is_held(USRQUOTA, UID), "a fresh mount already held a record");
    (v, ino)
}

/// The identity the fixture's ROOT directory belongs to. A rename charges the
/// DIRECTORIES it rewrites, not the file whose name moves, so the identity to
/// look for on those paths is this one and not the file's.
const DIR_OWNER: u32 = 1000;

/// Run one entry point on a fresh mount and require that it acquired `id`.
fn acquires(name: &str, id: u32, run: impl FnOnce(&mut Volume<MemImage>, u32)) {
    let (mut v, ino) = remounted();
    run(&mut v, ino);
    assert!(v.dquot_is_held(USRQUOTA, id),
            "{name} allocated without acquiring the record it charges against");
}

#[test]
fn a_write_acquires() {
    acquires("write_file", UID, |v, ino| { v.write_file(ino, 0, &vec![2u8; BLKSIZE]).unwrap(); });
}

#[test]
fn a_truncate_acquires() {
    acquires("truncate_file", UID, |v, ino| { v.truncate_file(ino, 0).unwrap(); });
}

#[test]
fn a_create_acquires() {
    acquires("create", UID, |v, _| { v.create(ROOT_INO, b"n", &spec(), None).unwrap(); });
}

#[test]
fn an_unnamed_file_acquires() {
    acquires("tmpfile", UID, |v, _| { v.tmpfile(ROOT_INO, &spec()).unwrap(); });
}

#[test]
fn a_removal_acquires() {
    acquires("remove", UID, |v, _| { v.remove(ROOT_INO, b"g", false, NOW).unwrap(); });
}

#[test]
fn a_link_acquires() {
    acquires("link", DIR_OWNER, |v, ino| { v.link(ROOT_INO, b"h", ino, NOW).unwrap(); });
}

#[test]
fn a_rename_acquires() {
    acquires("rename", DIR_OWNER, |v, _| {
        let r = Rename { from: ROOT_INO, old: b"f", to: ROOT_INO, new: b"z",
                         flags: 0, owner: (UID, UID), now: NOW };
        v.rename(&r).unwrap();
    });
}

#[test]
fn an_exchange_acquires() {
    acquires("rename EXCHANGE", DIR_OWNER, |v, _| {
        let r = Rename { from: ROOT_INO, old: b"f", to: ROOT_INO, new: b"g",
                         flags: vfs::namei::RENAME_EXCHANGE, owner: (UID, UID), now: NOW };
        v.rename(&r).unwrap();
    });
}

#[test]
fn an_attribute_write_acquires() {
    acquires("set_xattr", UID, |v, ino| {
        v.set_xattr(ino, "user.k", Some(b"v"), false, false).unwrap();
    });
}

#[test]
fn an_inline_conversion_acquires() {
    // `f` was written a whole block and is no longer inline; `g` never was
    // written and still holds its bytes inside its inode, so this is the file
    // on which the conversion actually does something.
    acquires("convert_inline", UID, |v, _| {
        let g = v.lookup(&v.read_inode(ROOT_INO).unwrap(), ROOT_INO, b"g").unwrap().ino;
        assert!(v.read_inode(g).unwrap().inline_data(), "the fixture file is not inline");
        v.convert_inline(g).unwrap();
    });
}

#[test]
fn a_fallocate_acquires() {
    acquires("fallocate", UID, |v, ino| { v.fallocate(ino, 0, 0, BLKSIZE as u64).unwrap(); });
}

#[test]
fn a_range_move_acquires() {
    acquires("move_file_range", UID, |v, ino| {
        let dst = v.lookup(&v.read_inode(ROOT_INO).unwrap(), ROOT_INO, b"g").unwrap().ino;
        v.write_file(dst, 0, &vec![3u8; BLKSIZE]).unwrap();
        let _ = v.move_file_range(ino, 0, dst, 0, BLKSIZE as u64);
    });
}

#[test]
fn a_span_acquires() {
    acquires("start_atomic_write", UID, |v, ino| { v.start_atomic_write(ino, false).unwrap(); });
}

#[test]
fn sealing_a_file_acquires() {
    acquires("enable_verity", UID, |v, ino| {
        v.enable_verity(ino, crate::verity::uapi::HASH_ALG_SHA256, 12, b"").unwrap();
    });
}

#[test]
fn a_writable_open_acquires_on_its_own() {
    // The reference's second belt: a handle opened for writing brings the
    // records in even when the operation that follows it is one this
    // filesystem reaches without a handle. A read-only handle does not, and
    // must not — nothing it can do allocates.
    let (mut v, ino) = remounted();
    let inode = v.read_inode(ino).unwrap();
    assert!(!v.dquot_is_held(USRQUOTA, UID));
    v.verity_file_open(&inode, ino, false).unwrap();
    assert!(!v.dquot_is_held(USRQUOTA, UID), "a read-only open read a quota file");
    v.dquot_initialize(ino).unwrap();
    assert!(v.dquot_is_held(USRQUOTA, UID));
}

#[test]
fn a_compressed_write_acquires() {
    // Its own fixture and its own remount: the compressed writer is a separate
    // entry point from the plain one and reaches the reservations by a
    // different road, so a missing acquisition there is invisible to every
    // test above.
    let (mut v, ino) = with_compressed_quota(crate::compress::algo::COMPRESS_LZ4, 2, 0);
    v.write_compressed(ino, 0, &vec![7u8; 4 * BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let mut o = Options::defaults();
    o.usrquota = true;
    let mut v = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), o, true).unwrap();
    v.set_clock(NOW.0);
    assert!(!v.dquot_is_held(USRQUOTA, UID), "a fresh mount already held a record");
    v.write_compressed(ino, 4 * BLKSIZE as u64, &vec![9u8; 4 * BLKSIZE]).unwrap();
    assert!(v.dquot_is_held(USRQUOTA, UID),
            "write_compressed reserved slots without acquiring the owner's record first");
}

#[test]
fn the_fixtures_root_owner_is_what_the_directory_tests_assert_on() {
    // If this drifts, the three tests that look for DIR_OWNER are asserting
    // about an identity nothing charges and would pass for the wrong reason.
    let (v, _) = remounted();
    let root = v.read_inode(ROOT_INO).unwrap();
    assert_eq!((root.uid, root.gid), (DIR_OWNER, DIR_OWNER));
}
