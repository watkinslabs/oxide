//! Atomic writes: what a span shows, what a crash shows, what a commit lands.

use super::policy::{self, AtomicFacts, AtomicGate, StartAction};
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::{NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

const NOW: (u64, u32) = (1_800_000_000, 7);

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

/// A file with two blocks of known contents, past the inline region.
fn with_two_blocks() -> (Volume<MemImage>, u32, Vec<u8>) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let mut body = vec![0xAAu8; BLKSIZE];
    body.extend_from_slice(&[0xBBu8; BLKSIZE]);
    v.write_file(ino, 0, &body).unwrap();
    (v, ino, body)
}

fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    reopen(v)
}

/// Reopen the medium WITHOUT a checkpoint of our own: whatever the volume put
/// there is what the next mount finds, which is the only way to see what a
/// crash would have left.
fn reopen(v: Volume<MemImage>) -> Volume<MemImage> {
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

fn whole(v: &Volume<MemImage>, ino: u32) -> Vec<u8> {
    let inode = v.read_inode(ino).unwrap();
    v.read_whole(&inode, ino).unwrap()
}

/// What the writer inside the span sees.
fn span_read(v: &Volume<MemImage>, ino: u32) -> Vec<u8> {
    let inode = v.read_inode(ino).unwrap();
    let mut out = vec![0u8; inode.size as usize];
    let got = v.atomic_read_file(&inode, ino, 0, &mut out).unwrap();
    out.truncate(got);
    out
}

fn ok_gate() -> AtomicGate {
    AtomicGate { writable_handle: true, owner_or_capable: true, is_reg: true, o_direct: false,
                 ro_mount: false }
}

// ------------------------------------------------------------------- ladder

#[test]
fn a_handle_that_cannot_write_cannot_start_commit_or_abort() {
    let g = AtomicGate { writable_handle: false, ..ok_gate() };
    let f = AtomicFacts::default();
    assert_eq!(policy::start_atomic_write(&g, &f), Err(Errno::Ebadf));
    assert_eq!(policy::commit_atomic_write(&g), Err(Errno::Ebadf));
    assert_eq!(policy::abort_atomic_write(&g), Err(Errno::Ebadf));
}

#[test]
fn the_handle_refusal_comes_before_the_owner_one() {
    let g = AtomicGate { writable_handle: false, owner_or_capable: false, ..ok_gate() };
    assert_eq!(policy::commit_atomic_write(&g), Err(Errno::Ebadf));
}

#[test]
fn a_caller_that_does_not_own_the_file_is_refused() {
    let g = AtomicGate { owner_or_capable: false, ..ok_gate() };
    assert_eq!(policy::start_atomic_write(&g, &AtomicFacts::default()), Err(Errno::Eacces));
    assert_eq!(policy::commit_atomic_write(&g), Err(Errno::Eacces));
    assert_eq!(policy::abort_atomic_write(&g), Err(Errno::Eacces));
}

#[test]
fn only_a_regular_file_gets_a_span() {
    let g = AtomicGate { is_reg: false, ..ok_gate() };
    assert_eq!(policy::start_atomic_write(&g, &AtomicFacts::default()), Err(Errno::Einval));
}

#[test]
fn a_handle_that_bypasses_the_cache_gets_no_span() {
    let g = AtomicGate { o_direct: true, ..ok_gate() };
    assert_eq!(policy::start_atomic_write(&g, &AtomicFacts::default()), Err(Errno::Einval));
    // And a write through one while a span is open is refused too.
    assert_eq!(policy::write_iter(true, true), Err(Errno::Eopnotsupp));
    assert_eq!(policy::write_iter(true, false), Ok(()));
    assert_eq!(policy::write_iter(false, true), Ok(()));
}

#[test]
fn the_type_refusal_comes_before_the_direct_one_and_both_before_the_mount() {
    let g = AtomicGate { is_reg: false, o_direct: true, ro_mount: true, ..ok_gate() };
    assert_eq!(policy::start_atomic_write(&g, &AtomicFacts::default()), Err(Errno::Einval));
    let g = AtomicGate { o_direct: true, ro_mount: true, ..ok_gate() };
    assert_eq!(policy::start_atomic_write(&g, &AtomicFacts::default()), Err(Errno::Einval));
    let g = AtomicGate { ro_mount: true, ..ok_gate() };
    assert_eq!(policy::start_atomic_write(&g, &AtomicFacts::default()), Err(Errno::Erofs));
}

#[test]
fn a_pinned_or_stubbornly_compressed_file_gets_no_span() {
    let f = AtomicFacts { pinned: true, ..AtomicFacts::default() };
    assert_eq!(policy::start_atomic_write(&ok_gate(), &f), Err(Errno::Einval));
    let f = AtomicFacts { compressed_undisableable: true, ..AtomicFacts::default() };
    assert_eq!(policy::start_atomic_write(&ok_gate(), &f), Err(Errno::Einval));
}

#[test]
fn starting_a_span_that_is_already_open_is_a_no_op() {
    let f = AtomicFacts { already_atomic: true, ..AtomicFacts::default() };
    assert_eq!(policy::start_atomic_write(&ok_gate(), &f), Ok(StartAction::AlreadyOpen));
}

#[test]
fn verity_may_not_be_turned_on_over_an_open_span() {
    assert_eq!(policy::enable_verity(true), Err(Errno::Eopnotsupp));
    assert_eq!(policy::enable_verity(false), Ok(()));
}

#[test]
fn a_range_clone_refuses_the_two_shapes_differently() {
    assert_eq!(policy::clone_range(true, false), Err(Errno::Eopnotsupp));
    assert_eq!(policy::clone_range(false, true), Err(Errno::Einval));
    assert_eq!(policy::clone_range(true, true), Err(Errno::Eopnotsupp));
    assert_eq!(policy::clone_range(false, false), Ok(()));
}

// -------------------------------------------------------------------- spans

#[test]
fn the_writer_reads_back_what_it_wrote() {
    let (mut v, ino, _) = with_two_blocks();
    v.start_atomic_write(ino, false).unwrap();
    v.atomic_write_file(ino, 0, b"new head").unwrap();
    assert_eq!(&span_read(&v, ino)[..8], b"new head");
    // And the rest of the block it did not write is still the file's.
    assert_eq!(span_read(&v, ino)[8], 0xAA);
}

#[test]
fn nobody_else_sees_the_span() {
    let (mut v, ino, body) = with_two_blocks();
    v.start_atomic_write(ino, false).unwrap();
    v.atomic_write_file(ino, 0, b"new head").unwrap();
    // The file's own blocks are untouched; only a reader that knows about the
    // span sees anything different.
    let inode = v.read_inode(ino).unwrap();
    let mut buf = vec![0u8; 8];
    let addr = match v.map_block(&inode, ino, 0).unwrap() {
        crate::volume::map::Mapped::At(a) => a,
        other => panic!("{other:?}"),
    };
    buf.copy_from_slice(&v.read_main_block(addr).unwrap()[..8]);
    assert_eq!(buf, body[..8]);
}

#[test]
fn a_crash_inside_a_span_leaves_the_file_alone() {
    let (mut v, ino, body) = with_two_blocks();
    v.start_atomic_write(ino, false).unwrap();
    v.atomic_write_file(ino, 0, b"never landed").unwrap();
    // A checkpoint lands while the span is open, which is exactly the state a
    // crash would leave behind.
    let v = remount(v);
    assert!(!v.is_atomic_file(ino));
    assert_eq!(whole(&v, ino), body);
}

#[test]
fn a_commit_lands_every_write_at_once() {
    let (mut v, ino, body) = with_two_blocks();
    v.start_atomic_write(ino, false).unwrap();
    v.atomic_write_file(ino, 0, b"one").unwrap();
    v.atomic_write_file(ino, BLKSIZE as u64, b"two").unwrap();
    v.commit_atomic_write(ino).unwrap();
    let v = remount(v);
    let got = whole(&v, ino);
    assert_eq!(&got[..3], b"one");
    assert_eq!(&got[3..8], &body[3..8]);
    assert_eq!(&got[BLKSIZE..BLKSIZE + 3], b"two");
    assert_eq!(got.len(), body.len());
}

#[test]
fn a_commit_is_durable_without_a_checkpoint_of_its_own() {
    let (mut v, ino, _) = with_two_blocks();
    v.commit().unwrap();
    v.start_atomic_write(ino, false).unwrap();
    v.atomic_write_file(ino, 0, b"durable").unwrap();
    v.commit_atomic_write(ino).unwrap();
    // No checkpoint here: whatever the commit put on the medium is all the
    // next mount gets.
    let v = reopen(v);
    assert_eq!(&whole(&v, ino)[..7], b"durable");
}

#[test]
fn an_abort_puts_the_file_back() {
    let (mut v, ino, body) = with_two_blocks();
    v.start_atomic_write(ino, false).unwrap();
    v.atomic_write_file(ino, 0, b"discarded").unwrap();
    v.abort_atomic_write(ino).unwrap();
    assert!(!v.is_atomic_file(ino));
    assert_eq!(whole(&v, ino), body);
    let v = remount(v);
    assert_eq!(whole(&v, ino), body);
}

#[test]
fn aborting_a_file_with_no_span_open_succeeds() {
    let (mut v, ino, body) = with_two_blocks();
    v.abort_atomic_write(ino).unwrap();
    assert_eq!(whole(&v, ino), body);
}

#[test]
fn an_abort_gives_the_space_back() {
    let (mut v, ino, _) = with_two_blocks();
    let before = v.valid_block_count;
    v.start_atomic_write(ino, false).unwrap();
    v.atomic_write_file(ino, 0, &vec![9u8; BLKSIZE * 2]).unwrap();
    assert!(v.valid_block_count > before, "the span's blocks were never charged");
    v.abort_atomic_write(ino).unwrap();
    // The COW inode and its blocks are gone; what is left is the file, plus
    // the node blocks its own rewrites took, which a checkpoint retires.
    assert!(v.valid_block_count < before + 2, "the span's blocks were not given back");
}

#[test]
fn a_span_that_grows_the_file_grows_it_only_on_commit() {
    let (mut v, ino, body) = with_two_blocks();
    v.start_atomic_write(ino, false).unwrap();
    let at = body.len() as u64;
    v.atomic_write_file(ino, at, b"appended").unwrap();
    v.commit_atomic_write(ino).unwrap();
    let v = remount(v);
    let got = whole(&v, ino);
    assert_eq!(got.len(), body.len() + 8);
    assert_eq!(&got[body.len()..], b"appended");
}

#[test]
fn an_aborted_span_does_not_grow_the_file() {
    let (mut v, ino, body) = with_two_blocks();
    v.start_atomic_write(ino, false).unwrap();
    v.atomic_write_file(ino, body.len() as u64, b"appended").unwrap();
    v.abort_atomic_write(ino).unwrap();
    assert_eq!(v.read_inode(ino).unwrap().size, body.len() as u64);
    let v = remount(v);
    assert_eq!(whole(&v, ino), body);
}

// ---------------------------------------------------------------- replacing

#[test]
fn a_replacing_span_shows_an_empty_file_at_once() {
    let (mut v, ino, _) = with_two_blocks();
    v.start_atomic_write(ino, true).unwrap();
    assert_eq!(v.read_inode(ino).unwrap().size, 0);
    assert!(span_read(&v, ino).is_empty());
}

#[test]
fn a_replacing_span_commits_only_what_it_wrote() {
    let (mut v, ino, _) = with_two_blocks();
    v.start_atomic_write(ino, true).unwrap();
    v.atomic_write_file(ino, 0, b"all there is").unwrap();
    v.commit_atomic_write(ino).unwrap();
    let v = remount(v);
    assert_eq!(whole(&v, ino), b"all there is".to_vec());
}

#[test]
fn a_replacing_span_does_not_show_the_old_bytes_around_a_partial_write() {
    let (mut v, ino, _) = with_two_blocks();
    v.start_atomic_write(ino, true).unwrap();
    v.atomic_write_file(ino, 4, b"xyz").unwrap();
    v.commit_atomic_write(ino).unwrap();
    let v = remount(v);
    assert_eq!(whole(&v, ino), vec![0, 0, 0, 0, b'x', b'y', b'z']);
}

#[test]
fn an_aborted_replacing_span_restores_the_whole_file() {
    let (mut v, ino, body) = with_two_blocks();
    v.start_atomic_write(ino, true).unwrap();
    v.atomic_write_file(ino, 0, b"gone").unwrap();
    v.abort_atomic_write(ino).unwrap();
    assert_eq!(whole(&v, ino), body);
    let v = remount(v);
    assert_eq!(whole(&v, ino), body);
}

#[test]
fn a_replacing_span_gives_back_the_blocks_it_replaced() {
    let (mut v, ino, _) = with_two_blocks();
    let before = v.read_inode(ino).unwrap().blocks;
    v.start_atomic_write(ino, true).unwrap();
    v.atomic_write_file(ino, 0, b"small").unwrap();
    v.commit_atomic_write(ino).unwrap();
    let v = remount(v);
    // Two blocks became one, so the file costs a block less than it did.
    assert!(v.read_inode(ino).unwrap().blocks < before,
            "the replaced block was never released");
}

// ----------------------------------------------------------- the COW inode

#[test]
fn the_cow_inode_is_an_orphan_while_the_span_is_open() {
    let (mut v, ino, _) = with_two_blocks();
    v.start_atomic_write(ino, false).unwrap();
    let cow = v.atomic_cow_ino(ino).unwrap();
    assert!(v.is_orphan(cow), "a crash would leak the span's blocks");
    assert!(v.is_cow_file(cow));
    assert_ne!(cow, ino);
}

#[test]
fn the_cow_inode_is_gone_once_the_span_ends() {
    let (mut v, ino, _) = with_two_blocks();
    v.start_atomic_write(ino, false).unwrap();
    let cow = v.atomic_cow_ino(ino).unwrap();
    v.atomic_write_file(ino, 0, b"x").unwrap();
    v.commit_atomic_write(ino).unwrap();
    assert!(!v.is_orphan(cow));
    assert!(!v.is_cow_file(cow));
    assert_eq!(v.atomic_cow_ino(ino), None);
}

#[test]
fn a_crash_mid_span_leaves_the_cow_inode_for_the_next_mount_to_reclaim() {
    let (mut v, ino, _) = with_two_blocks();
    v.start_atomic_write(ino, false).unwrap();
    let cow = v.atomic_cow_ino(ino).unwrap();
    v.atomic_write_file(ino, 0, &vec![3u8; BLKSIZE]).unwrap();
    let v = remount(v);
    assert!(!v.is_orphan(cow), "the mount did not reclaim the span's inode");
    assert!(v.atomic_files().is_empty());
}

#[test]
fn a_second_start_reuses_the_span_that_is_open() {
    let (mut v, ino, _) = with_two_blocks();
    v.start_atomic_write(ino, false).unwrap();
    let cow = v.atomic_cow_ino(ino).unwrap();
    v.start_atomic_write(ino, false).unwrap();
    assert_eq!(v.atomic_cow_ino(ino), Some(cow));
}

#[test]
fn a_pinned_file_is_refused_a_span_by_the_volume_too() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"p", &spec(), None).unwrap();
    v.set_pin_file(ino, 1).unwrap();
    assert_eq!(v.start_atomic_write(ino, false), Err(Errno::Einval));
}

#[test]
fn a_read_only_mount_opens_no_span() {
    let (v, ino, _) = with_two_blocks();
    let bytes = { let mut v = v; v.commit().unwrap(); v.into_source().snapshot() };
    let mut ro = Volume::mount_with(
        MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), false).unwrap();
    assert_eq!(ro.start_atomic_write(ino, false), Err(Errno::Erofs));
}

#[test]
fn a_span_takes_the_file_out_of_its_own_inode_first() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"small", &spec(), None).unwrap();
    v.write_file(ino, 0, b"tiny").unwrap();
    assert!(v.read_inode(ino).unwrap().inline_data());
    v.start_atomic_write(ino, false).unwrap();
    assert!(!v.read_inode(ino).unwrap().inline_data());
    v.atomic_write_file(ino, 0, b"BIG!").unwrap();
    v.commit_atomic_write(ino).unwrap();
    let v = remount(v);
    assert_eq!(whole(&v, ino), b"BIG!".to_vec());
}

#[test]
fn committing_a_file_with_no_span_open_just_makes_it_durable() {
    let (mut v, ino, body) = with_two_blocks();
    v.commit_atomic_write(ino).unwrap();
    let v = reopen(v);
    assert_eq!(whole(&v, ino), body);
}

#[test]
fn the_span_counts_the_blocks_it_wrote() {
    let (mut v, ino, _) = with_two_blocks();
    v.start_atomic_write(ino, false).unwrap();
    assert_eq!(v.atomic_write_count(ino), 0);
    v.atomic_write_file(ino, 0, b"a").unwrap();
    v.atomic_write_file(ino, BLKSIZE as u64, b"b").unwrap();
    assert_eq!(v.atomic_write_count(ino), 2);
}

#[test]
fn a_commit_that_fails_part_way_puts_every_block_it_moved_back() {
    let (mut v, ino, body) = with_two_blocks();
    v.start_atomic_write(ino, false).unwrap();
    v.atomic_write_file(ino, 0, b"one").unwrap();
    v.atomic_write_file(ino, BLKSIZE as u64, b"two").unwrap();
    // The span's second block is made to name an address outside the volume,
    // which is what a damaged index looks like from the commit's side.
    let cow = v.atomic_cow_ino(ino).unwrap();
    let (h, ofs) = v.dnode_for_write(cow, 1).unwrap();
    v.set_holder_addr(cow, h, ofs, 0x7000_0000).unwrap();
    assert_eq!(v.commit_atomic_write(ino), Err(Errno::Euclean));
    // Not half of each: the file is exactly what it was.
    assert_eq!(whole(&v, ino), body);
    let v = remount(v);
    assert_eq!(whole(&v, ino), body);
}

#[test]
fn verity_may_not_be_turned_on_over_an_open_span_at_the_volume_either() {
    let (mut v, ino, _) = with_two_blocks();
    v.start_atomic_write(ino, false).unwrap();
    assert_eq!(v.enable_verity(ino, crate::verity::uapi::HASH_ALG_SHA256, 12, &[]),
               Err(Errno::Eopnotsupp));
    v.abort_atomic_write(ino).unwrap();
    // And it is allowed again once the span is gone.
    assert!(v.enable_verity(ino, crate::verity::uapi::HASH_ALG_SHA256, 12, &[]).is_ok());
}
