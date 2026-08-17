//! Roll-forward recovery, end to end: a chain written into a live volume, the
//! volume abandoned without a checkpoint, and the bytes mounted again.
//!
//! A crash is simulated by taking the medium's bytes WITHOUT committing. That
//! is exactly what a power loss leaves — every block the mount wrote is on the
//! medium, and none of the table updates it held in memory are — so a mount of
//! those bytes reads the previous checkpoint and has to find the rest itself.

use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::*;
use crate::volume::dnode::{put32, put64};
use crate::volume::recover::fixture::*;
use crate::volume::recover::{marks, Recovery};
use crate::volume::Volume;
use alloc::vec;
use sectors::MemImage;

// ------------------------------------------- the writer and the reader agree
//
// These drive the path a caller takes — `write_file`, then `fsync`, then the
// power goes — with nothing crafted. They are the only tests that can catch
// the writer and the walk disagreeing, which is exactly what a forward pointer
// naming the wrong block does: every crafted chain still reads perfectly while
// no chain a real write produces can be followed at all.

#[test]
fn a_file_written_and_fsynced_survives_a_crash() {
    let (mut v, ino, _) = checkpointed(b"f");
    let want = grow_and_fsync(&mut v, ino, 0xEE);
    let v = crash(v);
    assert_eq!(whole(&v, ino), want);
    assert_eq!(v.read_inode(ino).expect("inode").size, want.len() as u64);
}

#[test]
fn a_file_written_and_not_fsynced_does_not_survive_a_crash() {
    let (mut v, ino, body) = checkpointed(b"f");
    grow(&mut v, ino, 0xEE);
    let v = crash(v);
    assert_eq!(whole(&v, ino), body);
}

#[test]
fn the_unmarked_nodes_a_write_leaves_do_not_stop_the_walk() {
    // `write_file` puts its own node blocks in the same log ahead of the
    // fsync's, so the walk only reaches the marked ones by passing through
    // them. A forward pointer that does not advance ends the chain here.
    let (mut v, ino, _) = checkpointed(b"f");
    grow(&mut v, ino, 0xE1);
    grow_and_fsync(&mut v, ino, 0xE2);
    let v = crash_ro(v);
    let found = v.scan_fsync_chain().expect("scan");
    assert!(!found.is_empty(), "the marked blocks sit past several unmarked ones");
    assert!(found.iter().all(|f| f.fsync && f.ino == ino));
}

#[test]
fn several_appends_under_one_fsync_all_survive() {
    let (mut v, ino, _) = checkpointed(b"f");
    grow(&mut v, ino, 0xA1);
    grow(&mut v, ino, 0xA2);
    let want = grow_and_fsync(&mut v, ino, 0xA3);
    let v = crash(v);
    assert_eq!(whole(&v, ino), want);
}

#[test]
fn a_write_to_a_file_nothing_promised_is_not_recovered() {
    // One file is made durable; the other is written in the same breath and
    // never promised. A crash must part them.
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let kept = v.create(ROOT_INO, b"kept", &spec(), None).expect("create kept");
    let lost = v.create(ROOT_INO, b"lost", &spec(), None).expect("create lost");
    v.write_file(kept, 0, &pattern(0x11)).expect("write kept");
    v.sync_data().unwrap();
    v.write_file(lost, 0, &pattern(0x22)).expect("write lost");
    v.sync_data().unwrap();
    v.commit().expect("commit");
    let want_kept = grow_and_fsync(&mut v, kept, 0xB1);
    let before_lost = whole(&v, lost);
    grow(&mut v, lost, 0xB2);
    let v = crash(v);
    assert_eq!(whole(&v, kept), want_kept, "the promised file comes back whole");
    assert_eq!(whole(&v, lost), before_lost, "the unpromised one is as the checkpoint left it");
}

#[test]
fn two_files_written_and_fsynced_both_survive() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let a = v.create(ROOT_INO, b"a", &spec(), None).expect("create a");
    let b = v.create(ROOT_INO, b"b", &spec(), None).expect("create b");
    v.write_file(a, 0, &pattern(0x11)).expect("write a");
    v.sync_data().unwrap();
    v.write_file(b, 0, &pattern(0x22)).expect("write b");
    v.sync_data().unwrap();
    v.commit().expect("commit");
    let wa = grow_and_fsync(&mut v, a, 0xA1);
    let wb = grow_and_fsync(&mut v, b, 0xB2);
    let v = crash(v);
    assert_eq!(whole(&v, a), wa);
    assert_eq!(whole(&v, b), wb);
}

#[test]
fn a_second_fsync_of_the_same_file_replaces_the_first() {
    let (mut v, ino, _) = checkpointed(b"f");
    grow_and_fsync(&mut v, ino, 0xC1);
    let want = grow_and_fsync(&mut v, ino, 0xC2);
    let v = crash(v);
    assert_eq!(whole(&v, ino), want);
}

#[test]
fn four_logs_put_the_chain_where_the_walk_looks_for_it() {
    let opts = Options { active_logs: 4, ..Options::defaults() };
    let (mut v, ino) = checkpointed_opts(b"f", opts);
    let want = grow_and_fsync(&mut v, ino, 0xD4);
    let v = remount_opts(v.into_source().snapshot(), true, opts);
    assert_eq!(whole(&v, ino), want);
}

#[test]
fn the_walk_starts_at_the_log_a_files_nodes_are_written_to() {
    for logs in [4u8, 6] {
        let opts = Options { active_logs: logs, ..Options::defaults() };
        let (mut v, ino) = checkpointed_opts(b"f", opts);
        v.write_file(ino, 0, b"x").expect("write");
        v.sync_data().unwrap();
        let start = v.fsync_chain_start();
        v.fsync(ino).expect("fsync");
        let block = v.read_block(start).expect("block");
        let f = crate::node::footer::parse(&block).expect("footer");
        assert!(f.is_fsync(), "{logs} logs: the chain head must be what fsync wrote");
        assert_eq!(f.ino, ino);
    }
}

// ------------------------------------------------------------------ replaying

#[test]
fn a_block_fsynced_but_not_checkpointed_survives_a_crash() {
    let (mut v, ino, body) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, true);
    let v = crash(v);
    let all = whole(&v, ino);
    assert_eq!(all.len(), BODY + BLKSIZE);
    assert_eq!(&all[..BODY], &body[..]);
    assert!(all[BODY..].iter().all(|&b| b == 0xEE));
}

#[test]
fn the_report_counts_what_was_put_back() {
    // The counters are read from the pass the MOUNT runs, which is the only
    // pass there is: by the time a caller holds the volume the chain is gone.
    let (mut v, ino, _) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, true);
    let v = crash_ro(v);
    let found = v.scan_fsync_chain().expect("scan");
    assert_eq!(found.len(), 1, "one marked block, the inode's");
    let mut v = remount(v.into_source().snapshot(), true);
    assert_eq!(v.recover().expect("second pass"), Recovery::Clean,
               "the mount already put it back");
    assert_eq!(v.read_inode(ino).expect("inode").size, (BODY + BLKSIZE) as u64);
}

#[test]
fn an_entry_is_restored_by_the_mount_itself() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"n", &spec(), None).expect("create");
    let saved = v.inode_bytes(ino).expect("bytes");
    v.remove(ROOT_INO, b"n", false, NOW).expect("remove");
    v.commit_with(crate::volume::commit::CpReason::Umount).expect("commit");
    v.write_chained_node(ino, ino, saved, marks::flag_word(0, true, true, true)).expect("node");
    let mut v = crash(v);
    let root = v.read_inode(ROOT_INO).expect("root");
    assert_eq!(v.lookup(&root, ROOT_INO, b"n").expect("entry").ino, ino);
    assert_eq!(v.recover().expect("second pass"), Recovery::Clean);
}

#[test]
fn a_chain_written_after_a_clean_unmount_is_still_replayed() {
    // The mark on the checkpoint says how THAT checkpoint was written, not
    // that nothing followed it. A mount that writes a chain and crashes
    // without checkpointing leaves the mark exactly as it found it, so a
    // recovery that trusts it walks past everything the fsync promised.
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"j", &spec(), None).expect("create");
    v.write_file(ino, 0, b"committed").expect("write");
    v.sync_data().unwrap();
    assert!(v.checkpoint().has(crate::flags::CP_UMOUNT_FLAG),
            "the image was left by a clean unmount and nothing has replaced it");
    assert_eq!(v.fsync(ino).expect("fsync"), crate::volume::fsync::CpReason::None);
    let v = crash(v);
    let root = v.read_inode(ROOT_INO).expect("root");
    let hit = v.lookup(&root, ROOT_INO, b"j").expect("the promised file is there");
    let inode = v.read_inode(hit.ino).expect("inode");
    assert_eq!(v.read_whole(&inode, hit.ino).expect("read"), b"committed".to_vec());
}

#[test]
fn the_recovered_size_is_the_one_the_fsync_recorded() {
    let (mut v, ino, _) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, true);
    let v = crash(v);
    assert_eq!(v.read_inode(ino).expect("inode").size, (BODY + BLKSIZE) as u64);
}

#[test]
fn a_block_written_without_an_fsync_does_not_survive() {
    let (mut v, ino, body) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, false);
    let v = crash(v);
    assert_eq!(whole(&v, ino), body);
}

#[test]
fn the_unfsynced_block_is_not_live_in_the_segment_table() {
    let (mut v, ino, _) = checkpointed(b"f");
    let (data, _) = append_block(&mut v, ino, 0xEE, false);
    let mut v = crash(v);
    v.load_segments().expect("segments");
    assert!(!v.addr_is_live(data), "a block nothing promised must stay free");
}

#[test]
fn the_recovered_block_is_live_in_the_segment_table() {
    let (mut v, ino, _) = checkpointed(b"f");
    let (data, _) = append_block(&mut v, ino, 0xEE, true);
    let mut v = crash(v);
    v.load_segments().expect("segments");
    assert!(v.addr_is_live(data), "a recovered block the allocator may hand out again");
}

#[test]
fn the_recovered_block_is_the_one_the_file_now_points_at() {
    let (mut v, ino, _) = checkpointed(b"f");
    let (data, _) = append_block(&mut v, ino, 0xEE, true);
    let v = crash(v);
    let inode = v.read_inode(ino).expect("inode");
    let m = v.map_block(&inode, ino, (BODY / BLKSIZE) as u64).expect("map");
    assert_eq!(m, crate::volume::map::Mapped::At(data));
}

#[test]
fn the_valid_block_count_rises_by_what_was_recovered() {
    let (mut v, ino, _) = checkpointed(b"f");
    let before = v.checkpoint().valid_block_count;
    append_block(&mut v, ino, 0xEE, true);
    let v = crash(v);
    assert!(v.checkpoint().valid_block_count > before);
}

#[test]
fn recovery_survives_a_further_remount() {
    let (mut v, ino, _) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, true);
    let v = crash(v);
    let v = remount(v.into_source().snapshot(), true);
    let all = whole(&v, ino);
    assert_eq!(all.len(), BODY + BLKSIZE);
    assert!(all[BODY..].iter().all(|&b| b == 0xEE));
}

#[test]
fn recovery_checkpoints_so_the_next_mount_finds_nothing() {
    let (mut v, ino, _) = checkpointed(b"f");
    append_block(&mut v, ino, 0xEE, true);
    let v = crash(v);
    let mut v = remount(v.into_source().snapshot(), true);
    assert_eq!(v.recover().expect("second"), Recovery::Clean);
}

#[test]
fn two_files_fsynced_in_sequence_both_recover() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let a = v.create(ROOT_INO, b"a", &spec(), None).expect("create a");
    let b = v.create(ROOT_INO, b"b", &spec(), None).expect("create b");
    let body = pattern(0x11);
    v.write_file(a, 0, &body).expect("write a");
    v.sync_data().unwrap();
    v.write_file(b, 0, &body).expect("write b");
    v.sync_data().unwrap();
    v.commit().expect("commit");
    append_block(&mut v, a, 0xA1, true);
    append_block(&mut v, b, 0xB2, true);
    let v = crash(v);
    let ra = whole(&v, a);
    let rb = whole(&v, b);
    assert_eq!(ra.len(), BODY + BLKSIZE);
    assert_eq!(rb.len(), BODY + BLKSIZE);
    assert!(ra[BODY..].iter().all(|&x| x == 0xA1));
    assert!(rb[BODY..].iter().all(|&x| x == 0xB2));
}

#[test]
fn a_second_fsync_of_the_same_file_wins() {
    let (mut v, ino, _) = checkpointed(b"f");
    append_block(&mut v, ino, 0xC1, true);
    append_block(&mut v, ino, 0xC2, true);
    let v = crash(v);
    let all = whole(&v, ino);
    assert!(all[BODY..].iter().all(|&x| x == 0xC2));
}

// ---------------------------------------------------- shapes other than blocks

#[test]
fn an_inline_files_bytes_are_recovered_from_inside_its_inode() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"i", &spec(), None).expect("create");
    v.write_file(ino, 0, b"before").expect("write");
    v.sync_data().unwrap();
    v.commit().expect("commit");
    assert!(v.read_inode(ino).expect("inode").inline_data());
    let inode = v.read_inode(ino).expect("inode");
    let (at, _) = inode.inline_data_span();
    let mut block = v.inode_bytes(ino).expect("bytes");
    block[at..at + 5].copy_from_slice(b"after");
    put64(&mut block, I_SIZE, 5);
    let flag = marks::flag_word(0, true, false, true);
    v.write_chained_node(ino, ino, block, flag).expect("node");
    let v = crash(v);
    assert!(v.read_inode(ino).expect("inode").inline_data());
    assert_eq!(whole(&v, ino), b"after".to_vec());
}

#[test]
fn an_inode_the_checkpoint_never_saw_is_created_from_its_marked_block() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"n", &spec(), None).expect("create");
    let saved = v.inode_bytes(ino).expect("bytes");
    v.remove(ROOT_INO, b"n", false, NOW).expect("remove");
    v.commit().expect("commit");
    assert!(v.read_inode(ino).is_err(), "the checkpoint must not know it");
    let flag = marks::flag_word(0, true, true, true);
    v.write_chained_node(ino, ino, saved, flag).expect("node");
    let v = crash(v);
    let inode = v.read_inode(ino).expect("recovered inode");
    assert_eq!(inode.links, 1);
    let root = v.read_inode(ROOT_INO).expect("root");
    assert_eq!(v.lookup(&root, ROOT_INO, b"n").expect("entry").ino, ino);
}

#[test]
fn an_inode_the_checkpoint_never_saw_and_no_mark_names_is_left_alone() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"n", &spec(), None).expect("create");
    let saved = v.inode_bytes(ino).expect("bytes");
    v.remove(ROOT_INO, b"n", false, NOW).expect("remove");
    v.commit().expect("commit");
    // Marked for recovery, but WITHOUT the dentry mark, so nothing states the
    // file's identity and there is no entry to restore it under.
    let flag = marks::flag_word(0, true, false, true);
    v.write_chained_node(ino, ino, saved, flag).expect("node");
    let v = crash(v);
    assert!(v.read_inode(ino).is_err());
    let root = v.read_inode(ROOT_INO).expect("root");
    assert!(v.lookup(&root, ROOT_INO, b"n").is_err());
}

#[test]
fn an_attribute_node_in_the_chain_is_adopted_by_its_inode() {
    let (mut v, ino, _) = checkpointed(b"f");
    assert_eq!(v.read_inode(ino).expect("inode").xattr_nid, 0);
    let nid = v.alloc_nid().expect("nid");
    let flag = marks::flag_word(marks::xattr_node_offset(), true, false, true);
    let addr = v.write_chained_node(nid, ino, vec![0u8; BLKSIZE], flag).expect("node");
    let mut v = crash(v);
    assert_eq!(v.read_inode(ino).expect("inode").xattr_nid, nid);
    assert_eq!(v.node_addr(nid).expect("addr"), addr);
    v.load_segments().expect("segments");
    assert!(v.addr_is_live(addr));
}

// -------------------------------------------- a block another file still holds

/// Two checkpointed files, and the address of the second block of the first.
fn two_files() -> (Volume<MemImage>, u32, u32, u32) {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let a = v.create(ROOT_INO, b"a", &spec(), None).expect("create a");
    let b = v.create(ROOT_INO, b"b", &spec(), None).expect("create b");
    v.write_file(a, 0, &pattern(0x33)).expect("write a");
    v.sync_data().unwrap();
    v.write_file(b, 0, &pattern(0x44)).expect("write b");
    v.sync_data().unwrap();
    v.commit().expect("commit");
    let inode = v.read_inode(a).expect("inode");
    let m = v.map_block(&inode, a, 1).expect("map");
    let crate::volume::map::Mapped::At(addr) = m else { panic!("block one of a") };
    (v, a, b, addr)
}

/// Hand `stolen` to `ino` at its second slot, the way a crashed generation
/// that had reassigned the block would leave it.
fn steal_into(v: &mut Volume<MemImage>, ino: u32, stolen: u32) {
    let inode = v.read_inode(ino).expect("inode");
    let mut block = v.inode_bytes(ino).expect("bytes");
    put32(&mut block, inode.addr_base() + 4, stolen);
    let flag = marks::flag_word(0, true, false, true);
    v.write_chained_node(ino, ino, block, flag).expect("node");
}

#[test]
fn a_block_a_recovered_file_claims_is_taken_from_its_old_owner() {
    let (mut v, a, b, stolen) = two_files();
    steal_into(&mut v, b, stolen);
    let v = crash(v);
    let ia = v.read_inode(a).expect("a");
    assert_eq!(v.map_block(&ia, a, 1).expect("map a"), crate::volume::map::Mapped::Hole);
    let ib = v.read_inode(b).expect("b");
    assert_eq!(v.map_block(&ib, b, 1).expect("map b"), crate::volume::map::Mapped::At(stolen));
}

#[test]
fn a_block_taken_from_its_old_owner_stays_live() {
    let (mut v, _, b, stolen) = two_files();
    steal_into(&mut v, b, stolen);
    let mut v = crash(v);
    v.load_segments().expect("segments");
    assert!(v.addr_is_live(stolen), "a block the recovered file points at must not be free");
}

#[test]
fn a_block_no_one_else_holds_is_left_alone() {
    let (mut v, ino, _) = checkpointed(b"f");
    let (data, _) = append_block(&mut v, ino, 0xEE, true);
    let mut before = crash_ro(v);
    before.load_segments().expect("segments");
    assert!(!before.addr_is_live(data), "the checkpoint has never heard of it");
    let mut v = remount(before.into_source().snapshot(), true);
    v.load_segments().expect("segments");
    assert!(v.addr_is_live(data));
}
