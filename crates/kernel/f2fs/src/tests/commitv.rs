//! Writing a checkpoint: the pack alternates, the version rises, and the
//! tables reach the medium.

use super::*;
use crate::mode::S_IFREG;
use crate::opts::{AllocMode, Options};
use crate::test_image::{self, ROOT_INO};
use crate::volume::{NewInode, Volume};
use alloc::vec;
use sectors::MemImage;

const NOW: (u64, u32) = (1_800_000_000, 0);

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

fn vol() -> Volume<MemImage> { test_image::with_root().mount_rw().unwrap() }

fn reopen(v: Volume<MemImage>) -> Volume<MemImage> {
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

#[test]
fn a_mount_that_changed_nothing_writes_no_checkpoint() {
    // A checkpoint costs the whole pack; writing one per sync on an idle
    // filesystem burns the medium for no state change.
    let mut v = vol();
    let before = v.checkpoint().version;
    v.commit().unwrap();
    assert_eq!(v.checkpoint().version, before);
    assert!(!v.is_dirty());
}

#[test]
fn a_write_marks_the_mount_dirty() {
    let mut v = vol();
    assert!(!v.is_dirty());
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    assert!(v.is_dirty());
}

#[test]
fn an_unmount_checkpoint_marks_the_shutdown_clean_and_carries_every_summary() {
    // The flag is what tells the next mount whether a crash happened, so it
    // must mean something: set here, clear on an ordinary flush.
    use crate::volume::commit::CpReason;
    let mut v = vol();
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.commit_with(CpReason::Umount).unwrap();
    assert!(v.checkpoint().node_summaries_present());
    assert_eq!(v.checkpoint().pack_total_block_count,
               CP_PACKS + NR_CURSEG_PERSIST_TYPE as u32);
    let v = reopen(v);
    assert!(v.checkpoint().node_summaries_present());
}

#[test]
fn the_open_logs_resume_after_an_ordinary_checkpoint_too() {
    // The node summaries are not in that pack, so a reader has to find them
    // in the summary area; counting back from the pack's end would land past
    // its tail.
    let mut v = vol();
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.commit().unwrap();
    let want: alloc::vec::Vec<(u32, u16)> =
        v.logs().iter().map(|c| (c.segno, c.next_blkoff)).collect();
    let v = reopen(v);
    assert!(!v.checkpoint().node_summaries_present());
    let got: alloc::vec::Vec<(u32, u16)> =
        v.logs().iter().map(|c| (c.segno, c.next_blkoff)).collect();
    assert_eq!(got, want);
    let root = v.root().unwrap();
    assert!(v.lookup(&root, ROOT_INO, b"f").is_ok());
}

#[test]
fn a_checkpoint_raises_the_version_by_one() {
    let mut v = vol();
    let before = v.checkpoint().version;
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.commit().unwrap();
    assert_eq!(v.checkpoint().version, before + 1);
    assert!(!v.is_dirty());
}

#[test]
fn a_checkpoint_goes_to_the_other_pack() {
    // Writing over the pack being replaced is what a crash mid-write would
    // destroy; the alternation is the whole recovery guarantee.
    let mut v = vol();
    let first = v.checkpoint().pack;
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.commit().unwrap();
    assert_ne!(v.checkpoint().pack, first);
    v.create(ROOT_INO, b"g", &spec(), None).unwrap();
    v.commit().unwrap();
    assert_eq!(v.checkpoint().pack, first);
}

#[test]
fn the_pack_not_written_still_holds_the_previous_checkpoint() {
    // The alternation is only worth anything if the older pack survives whole.
    // Damage the newest pack and the volume must fall back to the one before
    // it rather than refusing to mount.
    let mut v = vol();
    v.create(ROOT_INO, b"first", &spec(), None).unwrap();
    v.commit().unwrap();
    let old_ver = v.checkpoint().version;
    v.create(ROOT_INO, b"second", &spec(), None).unwrap();
    v.commit().unwrap();
    let total = v.checkpoint().pack_total_block_count;
    let start = v.checkpoint().start(test_image::CP_BLKADDR, BLKS_PER_SEG);
    let mut bytes = v.into_source().snapshot();
    // Tear the newest pack's tail, which is what an interrupted write leaves.
    let tail = (start + total - 1) as usize * BLKSIZE;
    bytes[tail + CP_CHECKPOINT_VER] ^= 0xFF;
    let v = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes),
                               Options::defaults(), true).unwrap();
    assert_eq!(v.checkpoint().version, old_ver);
    let root = v.root().unwrap();
    assert!(v.lookup(&root, ROOT_INO, b"first").is_ok(), "the older pack lost its state");
    assert!(v.lookup(&root, ROOT_INO, b"second").is_err());
}

#[test]
fn a_remount_picks_the_pack_the_last_checkpoint_wrote() {
    let mut v = vol();
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.commit().unwrap();
    let (want_pack, want_ver) = (v.checkpoint().pack, v.checkpoint().version);
    let v = reopen(v);
    assert_eq!(v.checkpoint().pack, want_pack);
    assert_eq!(v.checkpoint().version, want_ver);
}

#[test]
fn the_pack_written_is_the_one_a_reader_validates() {
    let mut v = vol();
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.commit().unwrap();
    // An ordinary checkpoint is NOT a clean unmount, and says so: the node
    // logs' summaries stay in the summary area and the pack is shorter.
    assert!(!v.checkpoint().node_summaries_present());
    assert!(!v.checkpoint().has(CP_COMPACT_SUM_FLAG));
    assert_eq!(v.checkpoint().pack_total_block_count, CP_PACKS + NR_CURSEG_DATA_TYPE as u32);
    assert_eq!(v.checkpoint().pack_start_sum, 1);
}

#[test]
fn a_change_only_in_memory_is_invisible_to_a_remount() {
    // The proof that the checkpoint is what makes a change durable.
    let mut v = vol();
    v.create(ROOT_INO, b"ghost", &spec(), None).unwrap();
    let v = reopen(v);
    let root = v.root().unwrap();
    assert!(v.lookup(&root, ROOT_INO, b"ghost").is_err());
}

#[test]
fn the_node_table_reaches_the_medium_through_the_journal() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.commit().unwrap();
    let addr = v.node_addr(ino).unwrap();
    let v = reopen(v);
    assert_eq!(v.node_addr(ino).unwrap(), addr);
}

#[test]
fn a_journal_too_small_for_the_changes_pushes_them_into_the_table() {
    // More node changes than the journal holds must be written into the table
    // blocks with the version bit flipped; keeping them in memory would lose
    // them all at unmount.
    let mut v = vol();
    let mut inos = alloc::vec::Vec::new();
    for i in 0..(NAT_JOURNAL_ENTRIES + 20) {
        let name = alloc::format!("f{i:03}");
        inos.push(v.create(ROOT_INO, name.as_bytes(), &spec(), None).unwrap());
    }
    v.commit().unwrap();
    let want: alloc::vec::Vec<u32> = inos.iter().map(|&i| v.node_addr(i).unwrap()).collect();
    let v = reopen(v);
    for (i, ino) in inos.iter().enumerate() {
        assert_eq!(v.node_addr(*ino).unwrap(), want[i], "node {ino} moved");
    }
    let root = v.root().unwrap();
    for i in 0..(NAT_JOURNAL_ENTRIES + 20) {
        let name = alloc::format!("f{i:03}");
        assert!(v.lookup(&root, ROOT_INO, name.as_bytes()).is_ok(), "lost {name}");
    }
}

#[test]
fn the_node_tables_version_bit_flips_when_a_block_is_rewritten() {
    let mut v = vol();
    for i in 0..(NAT_JOURNAL_ENTRIES + 20) {
        let name = alloc::format!("f{i:03}");
        v.create(ROOT_INO, name.as_bytes(), &spec(), None).unwrap();
    }
    let before = v.checkpoint_bytes().to_vec();
    v.commit().unwrap();
    assert_ne!(v.checkpoint_bytes(), &before[..], "the bitmaps did not change");
}

#[test]
fn the_segment_table_survives_a_remount() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![3u8; 2 * BLKSIZE]).unwrap();
    v.commit().unwrap();
    let want: alloc::vec::Vec<u16> =
        (0..test_image::SEG_MAIN).map(|s| v.seg_entry(s).unwrap().valid_blocks()).collect();
    let v = reopen(v);
    for s in 0..test_image::SEG_MAIN {
        assert_eq!(v.seg_entry(s).unwrap().valid_blocks(), want[s as usize], "segment {s}");
    }
}

#[test]
fn the_open_logs_resume_where_the_checkpoint_left_them() {
    // A log that resumed at the wrong offset would hand out a block already
    // in use.
    let mut v = vol();
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.commit().unwrap();
    let want: alloc::vec::Vec<(u32, u16)> =
        v.logs().iter().map(|c| (c.segno, c.next_blkoff)).collect();
    let v = reopen(v);
    let got: alloc::vec::Vec<(u32, u16)> =
        v.logs().iter().map(|c| (c.segno, c.next_blkoff)).collect();
    assert_eq!(got, want);
}

#[test]
fn a_write_after_a_remount_does_not_reuse_a_live_block() {
    let mut v = vol();
    let a = v.create(ROOT_INO, b"a", &spec(), None).unwrap();
    v.write_file(a, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.commit().unwrap();
    let inode = v.read_inode(a).unwrap();
    let crate::volume::map::Mapped::At(live) = v.map_block(&inode, a, 0).unwrap()
        else { panic!("no block") };
    let mut v = reopen(v);
    let b = v.create(ROOT_INO, b"b", &spec(), None).unwrap();
    v.write_file(b, 0, &vec![2u8; BLKSIZE]).unwrap();
    let inode = v.read_inode(b).unwrap();
    let crate::volume::map::Mapped::At(fresh) = v.map_block(&inode, b, 0).unwrap()
        else { panic!("no block") };
    assert_ne!(fresh, live);
    // And the first file still reads what it held.
    let inode = v.read_inode(a).unwrap();
    assert_eq!(v.read_whole(&inode, a).unwrap(), vec![1u8; BLKSIZE]);
}

#[test]
fn the_counts_the_checkpoint_records_survive_a_remount() {
    let mut v = vol();
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.create(ROOT_INO, b"d", &NewInode { mode: crate::mode::S_IFDIR | 0o755, ..spec() }, None)
        .unwrap();
    v.commit().unwrap();
    let (nodes, inodes, blocks) = (
        v.checkpoint().valid_node_count,
        v.checkpoint().valid_inode_count,
        v.checkpoint().valid_block_count,
    );
    let v = reopen(v);
    assert_eq!(v.checkpoint().valid_node_count, nodes);
    assert_eq!(v.checkpoint().valid_inode_count, inodes);
    assert_eq!(v.checkpoint().valid_block_count, blocks);
    assert!(nodes >= 3);
}

#[test]
fn a_recycling_mount_reuses_a_partly_used_segment() {
    // The other allocation shape the reference has: instead of opening an
    // empty segment, a log takes the free blocks of one already in use.
    let mut opts = Options::defaults();
    opts.alloc_mode = AllocMode::Reuse;
    let mut v = test_image::with_root().mount_opts(opts).unwrap();
    v.load_segments().unwrap();
    let victim = test_image::SEG_MAIN - 1;
    v.update_seg(test_image::MAIN_BLKADDR + victim * BLKS_PER_SEG + 5, true).unwrap();
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    let log = &v.logs()[CURSEG_WARM_DATA];
    assert_eq!(log.segno, victim);
    assert_eq!(log.alloc_type, ALLOC_SSR);
    assert_eq!(log.next_blkoff, 0);
}

#[test]
fn an_appending_mount_opens_an_empty_segment() {
    let mut v = vol();
    v.load_segments().unwrap();
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    let log = &v.logs()[CURSEG_WARM_DATA];
    assert_eq!(log.alloc_type, ALLOC_LFS);
    assert_eq!(log.next_blkoff, 0);
    assert_eq!(v.seg_valid(log.segno), 0);
}

#[test]
fn a_read_only_mount_commits_nothing_and_reports_success() {
    let mut v = test_image::with_root().mount().unwrap();
    let before = v.checkpoint().version;
    assert!(v.commit().is_ok());
    assert_eq!(v.checkpoint().version, before);
}
