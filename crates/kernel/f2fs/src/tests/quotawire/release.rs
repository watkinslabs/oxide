//! Space given back when an attribute block or a directory block goes,
//! and space promised before it is occupied.

use super::*;
use super::fixture::*;

// ------------------------------------------------ space given back on release

#[test]
fn an_attribute_block_that_is_dropped_gives_its_space_back() {
    let mut v = with_quota(0, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec_of(UID), None).unwrap();
    let before = space(&mut v);
    v.set_xattr(ino, "user.big", Some(&vec![7u8; 1024]), false, false).unwrap();
    assert!(space(&mut v) > before, "an out-of-line attribute block is charged");
    v.remove_xattr(ino, "user.big").unwrap();
    assert_eq!(space(&mut v), before, "the attribute block's space never came back");
}

#[test]
fn a_directory_block_emptied_of_every_name_gives_its_space_back() {
    let mut v = with_quota(0, 0, true);
    let dir_spec =
        NewInode { mode: crate::mode::S_IFDIR | 0o755, uid: UID, gid: UID, rdev: 0, now: NOW };
    let dir = v.create(ROOT_INO, b"d", &dir_spec, None).unwrap();
    // Long names, so the inline area a small directory keeps its entries in
    // is exhausted by a handful of them rather than by hundreds of inodes
    // this image has no room for.
    let mut names = Vec::new();
    for i in 0..40u32 {
        let n = alloc::format!("{i:0>200}");
        v.create(dir, n.as_bytes(), &spec_of(UID), None).unwrap();
        names.push(n);
    }
    let peak = space(&mut v);
    assert!(peak > 0, "the directory never grew past its inline area");
    for n in &names { v.remove(dir, n.as_bytes(), false, NOW).unwrap(); }
    // What is left is the node block that maps the directory's data, which
    // this did not free; the inode itself is never charged as space. So the
    // charge has to be exactly the blocks the directory still holds, and a
    // released block still being paid for shows up as the difference.
    let held = (v.count_blocks(dir).unwrap() - 1) * BLKSIZE as u64;
    assert!(held < peak, "no directory block was released at all");
    assert_eq!(
        space(&mut v),
        held,
        "a directory that shrank kept paying for the blocks it gave back",
    );
}

// ------------------------------------- space promised before it is occupied

/// The record's promise, which is never stored and so is only ever readable
/// from the mount that made it.
fn promised(v: &mut Volume<MemImage>) -> u64 {
    v.quota_record(USRQUOTA, UID).unwrap().rsvspace
}

#[test]
fn a_promise_is_refused_taken_up_and_given_back_against_the_same_limit() {
    // The call sites that pair these two around an allocation are the write
    // path's; this is the volume half they call, and the reason it exists:
    // the limit is answered BEFORE the block is made, and an allocation that
    // then fails owes nothing.
    let mut v = with_quota(4, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec_of(UID), None).unwrap();
    let hard = qi::units(4);

    v.reserve_space(ino, hard).unwrap();
    assert_eq!(promised(&mut v), hard, "the promise was not recorded");
    assert_eq!(space(&mut v), 0, "a promise occupies nothing");
    assert_eq!(
        v.reserve_space(ino, BLKSIZE as u64),
        Err(Errno::Edquot),
        "a promise nobody counted would be handed out twice",
    );

    v.release_reserved_space(ino, hard).unwrap();
    assert_eq!(promised(&mut v), 0);
    v.reserve_space(ino, hard).unwrap();
    v.claim_space(ino, hard).unwrap();
    assert_eq!(promised(&mut v), 0, "the promise was taken up");
    assert_eq!(space(&mut v), hard, "and is occupied now, once, not twice");
}
