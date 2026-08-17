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

#[test]
fn a_write_the_quota_refuses_charges_nothing_and_leaves_no_promise() {
    // Two blocks' worth of limit, spent, then a third block asked for.
    let per_block = BLKSIZE as u64 / crate::quota::uapi::SPACE_UNIT;
    let mut v = with_quota(2 * per_block, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec_of(UID), None).unwrap();
    v.write_one_block(ino, 0, 0, &[1u8; 16]).unwrap();
    v.write_one_block(ino, 1, 0, &[1u8; 16]).unwrap();
    assert_eq!(space(&mut v), 2 * BLKSIZE as u64);
    assert_eq!(promised(&mut v), 0, "a promise nobody took up would deny the next write");

    assert_eq!(v.write_one_block(ino, 2, 0, &[1u8; 16]), Err(Errno::Edquot));
    assert_eq!(space(&mut v), 2 * BLKSIZE as u64, "the refused write charged the owner anyway");
    assert_eq!(promised(&mut v), 0, "and left a promise standing against every later write");
}

#[test]
fn a_write_the_volume_has_no_room_for_gives_the_promise_back() {
    // No quota limit at all: the refusal here is the VOLUME's, which is the
    // case the promise exists for — the owner is told nothing was spent
    // because nothing was.
    let mut v = with_quota(0, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec_of(UID), None).unwrap();
    let mut index = 0u64;
    loop {
        // Through the file interface, which is the path that converts an
        // inline file out of its inode before any block is asked for.
        match v.write_file(ino, index * BLKSIZE as u64, &[7u8; BLKSIZE]) {
            Ok(0) | Err(Errno::Enospc) => break,
            Ok(_) => index += 1,
            Err(e) => panic!("unexpected {e:?} at block {index}"),
        }
        assert!(index < 1 << 16, "the volume never ran out of room");
    }
    assert!(index > 0, "nothing was written before the volume filled");
    // The owner is charged for exactly the blocks its file holds. Comparing
    // against the count BEFORE the failed call would be wrong for a different
    // reason: that call can allocate a node block on its way to the data
    // block that fails, and a node block it really got is really charged.
    let held = (v.count_blocks(ino).unwrap() - 1) * BLKSIZE as u64;
    assert_eq!(space(&mut v), held, "the owner pays for a block its file does not have");
    assert_eq!(promised(&mut v), 0, "the promise the failed allocation held was never returned");
}

#[test]
fn moving_an_inline_file_out_into_a_block_charges_that_block() {
    let mut v = with_quota(0, 0, true);
    let ino = v.create(ROOT_INO, b"f", &spec_of(UID), None).unwrap();
    v.write_file(ino, 0, b"small").unwrap();
    v.sync_data().unwrap();
    assert_eq!(space(&mut v), 0, "an inline file occupies its inode and nothing else");
    v.convert_inline(ino).unwrap();
    assert_eq!(space(&mut v), BLKSIZE as u64, "the block the bytes moved into is the owner's");
    assert_eq!(promised(&mut v), 0);
    // Writing into that block again finds it already there and charges nothing.
    v.write_one_block(ino, 0, 0, b"more").unwrap();
    assert_eq!(space(&mut v), BLKSIZE as u64);
}

#[test]
fn a_node_block_the_log_has_no_room_for_gives_the_promise_back() {
    // The other half of the same rule: a NODE a file needs is promised before
    // the log is asked for a block, and the log running dry gives it back.
    // Nodes and data are written to DIFFERENT logs, so draining the data log
    // is not enough — each attempt below takes a node block for a direct node
    // and then fails on the data block, until the node log is dry as well and
    // the failure moves to the node itself.
    let mut v = with_quota(0, 0, true);
    let filler = v.create(ROOT_INO, b"filler", &spec_of(UID), None).unwrap();
    let deep = v.create(ROOT_INO, b"deep", &spec_of(UID), None).unwrap();
    // Out of its inode before the volume fills, so nothing below is the
    // inode's own write.
    v.write_file(deep, 0, &[1u8; 16]).unwrap();
    v.sync_data().unwrap();
    v.convert_inline(deep).unwrap();
    let mut index = 0u64;
    loop {
        match v.write_file(filler, index * BLKSIZE as u64, &[7u8; BLKSIZE]) {
            Ok(0) | Err(Errno::Enospc) => break,
            Ok(_) => index += 1,
            Err(e) => panic!("unexpected {e:?} at block {index}"),
        }
        assert!(index < 1 << 16, "the volume never ran out of room");
    }
    // Each of these needs a direct node the inode's own slots cannot hold.
    let apb = v.read_inode(deep).unwrap().addrs_per_inode() as u64;
    let per_node = crate::uapi::DEF_ADDRS_PER_BLOCK as u64;
    for n in 1..=1024u64 {
        let at = (apb + n * per_node) * BLKSIZE as u64;
        assert_eq!(v.write_file(deep, at, &[1u8; 16]), Err(Errno::Enospc), "n={n}");
    }
    assert_eq!(promised(&mut v), 0, "a promise no allocation could use was never given back");
    // What the owner is charged is NOT compared with what its files hold
    // here: a write that takes a node block and then fails on its data block
    // leaves that node allocated and unreferenced, so the charge is right and
    // the tree is short. That leak is a separate defect and has its own row.
}
