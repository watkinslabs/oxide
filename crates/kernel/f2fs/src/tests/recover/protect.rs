//! What replay must put beyond the allocator's reach before it writes a
//! single block.
//!
//! Replay is not a reader. It rewrites nodes, it creates inodes, it adds
//! directory entries — and every one of those writes comes off the tail of a
//! log that is standing exactly where the crashed mount left the chain. The
//! reference reaches safety by another route: it writes nothing to the main
//! area during the pass at all, holding every recovered node dirty in memory
//! and opening fresh segments only when the closing checkpoint flushes them.
//! This build has no such cache, so the protection has to come first instead.

use crate::test_image::{self, ROOT_INO};
use crate::uapi::*;
use crate::volume::dnode::put32;
use crate::volume::recover::fixture::*;
use crate::volume::recover::marks;

#[test]
fn an_inline_files_bytes_are_never_read_as_addresses() {
    // The inline region and the address array are the same bytes. A pass that
    // walks a recovered inode's array without asking whether the file's data
    // lives there marks live whatever its text decodes to — a block taken out
    // of the allocator's hands, and a count raised for a block nothing owns.
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"i", &spec(), None).expect("create");
    v.write_file(ino, 0, b"before").expect("write");
    v.commit().expect("commit");
    let free = v.fsync_chain_start() + 50;
    v.load_segments().expect("segments");
    assert!(!v.addr_is_live(free), "the fixture must point at a free block");
    let inode = v.read_inode(ino).expect("inode");
    let (at, _) = inode.inline_data_span();
    let mut block = v.inode_bytes(ino).expect("bytes");
    put32(&mut block, at, free);
    let before = v.checkpoint().valid_block_count;
    v.write_chained_node(ino, ino, block, marks::flag_word(0, true, false, true)).expect("node");
    let mut v = crash(v);
    v.load_segments().expect("segments");
    assert!(!v.addr_is_live(free), "the file's own text is not an address");
    assert_eq!(v.checkpoint().valid_block_count, before, "and nothing was charged for it");
}

// ------------------------------------------- the chain is not written over

#[test]
fn a_log_standing_over_the_chain_moves_before_the_replay_writes() {
    // Replay WRITES, and the log it writes through is standing exactly where
    // the crashed mount left the chain — so unless it is moved first, the
    // first node replay puts back lands on a block replay has not read yet.
    // The reference reaches the same end by another route: it writes nothing
    // to the main area during the pass at all, holding every recovered node
    // dirty in memory and allocating fresh segments only when the closing
    // checkpoint flushes them. This build has no such cache; its writes go
    // down as they are made, so the protection has to come first instead.
    let (mut v, ino, _) = checkpointed(b"f");
    let (data, node) = append_block(&mut v, ino, 0xEE, true);
    let before = crash_ro(v);
    let head = before.fsync_chain_start();
    let seg = before.super_block().segno_of(head).expect("segment");
    assert_eq!(before.super_block().segno_of(node), Some(seg), "the fixture puts it there");
    let mut v = remount(before.into_source().snapshot(), true);
    assert_ne!(v.logs()[CURSEG_WARM_NODE].segno, seg, "the log moved off the chain");
    v.load_segments().expect("segments");
    assert!(v.addr_is_live(data), "and the block it promised is still there");
}

#[test]
fn a_chain_of_several_promises_is_replayed_whole() {
    // The one that fails if the log is left standing: replay reads the chain
    // block by block and writes between the reads, so a log still pointing
    // into the chain overwrites the blocks the later reads need.
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let mut inos = alloc::vec::Vec::new();
    for name in [b"a", b"b", b"c", b"d"] {
        let ino = v.create(ROOT_INO, name, &spec(), None).expect("create");
        v.write_file(ino, 0, &pattern(0x10)).expect("write");
        inos.push(ino);
    }
    v.commit().expect("commit");
    for (i, &ino) in inos.iter().enumerate() { append_block(&mut v, ino, 0xB0 + i as u8, true); }
    let v = crash(v);
    for (i, &ino) in inos.iter().enumerate() {
        let all = whole(&v, ino);
        assert_eq!(all.len(), BODY + BLKSIZE, "file {i} came back short");
        assert!(all[BODY..].iter().all(|&b| b == 0xB0 + i as u8), "file {i} holds other bytes");
    }
}
