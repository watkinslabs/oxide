//! When a barrier is owed, which member owes it, and — for the checkpoint —
//! the ORDER the commands reach the medium in.
//!
//! The order assertions carry the durability contract. A pre-flush issued after
//! the commit block it exists to precede leaves every count identical and the
//! guarantee gone, and the only observation that distinguishes the two is a
//! power cut. So the fixture records a command SEQUENCE and the tests compare
//! against it position by position.

use super::*;

use block::durability::{FUA, PREFLUSH};
use sectors::source::Cmd;
use sectors::MemImage;

use crate::mode::S_IFREG;
use crate::opts::{FsyncMode, Options};
use crate::test_image::{self, ROOT_INO};
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 0);

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

/// A read-write mount over an image that behaves as a device holding
/// acknowledged writes in a volatile cache — which is the only kind of device
/// any of this is for.
fn cached(opts: Options) -> Volume<MemImage> {
    let bytes = test_image::with_root().finish();
    let img = MemImage::from_bytes(crate::uapi::BLKSIZE as u32, bytes).with_write_cache();
    Volume::mount_with(img, opts, true).unwrap()
}

fn cmds(v: &Volume<MemImage>) -> alloc::vec::Vec<Cmd> { v.source_ref().commands() }

// ---- the decisions ----

#[test]
fn an_fsync_chain_owes_a_barrier_by_default() {
    assert!(fsync_needs_flush(true, FsyncMode::Posix, false));
    assert!(fsync_needs_flush(true, FsyncMode::Strict, false));
}

#[test]
fn a_mount_that_asked_for_no_barriers_owes_none_in_any_mode() {
    for m in [FsyncMode::Posix, FsyncMode::Strict, FsyncMode::Nobarrier] {
        assert!(!fsync_needs_flush(false, m, false), "nobarrier mount must fence nothing");
    }
}

#[test]
fn fsync_mode_nobarrier_drops_the_barrier_without_dropping_the_checkpoints() {
    assert!(!fsync_needs_flush(true, FsyncMode::Nobarrier, false));
}

#[test]
fn an_atomic_commit_needs_no_barrier_because_its_chain_is_self_ordering() {
    assert!(!fsync_needs_flush(true, FsyncMode::Posix, true));
}

#[test]
fn the_commit_block_promises_both_halves_unless_the_mount_refused_barriers() {
    let d = commit_block_durability(true);
    assert!(d.contains(PREFLUSH) && d.contains(FUA));
    assert!(commit_block_durability(false).is_empty());
}

#[test]
fn the_checkpoint_pass_skips_the_member_that_carries_the_pack() {
    // Member zero's ordering is the commit block's own business; fencing it
    // here would cost a second barrier for the one guarantee.
    let t = checkpoint_flush_targets(true, 3, 0b111);
    assert!(!t.contains(0) && t.contains(1) && t.contains(2));
    assert_eq!(t.iter().collect::<alloc::vec::Vec<_>>(), alloc::vec![1, 2]);
}

#[test]
fn the_checkpoint_pass_skips_members_nothing_has_written_to() {
    let t = checkpoint_flush_targets(true, 4, 0b1001);
    assert_eq!(t.iter().collect::<alloc::vec::Vec<_>>(), alloc::vec![3]);
}

#[test]
fn a_single_member_volume_has_nothing_to_fence_before_its_commit_block() {
    assert!(checkpoint_flush_targets(true, 1, 0b1).is_empty());
}

#[test]
fn a_nobarrier_mount_fences_no_member_however_dirty() {
    assert!(checkpoint_flush_targets(false, 4, 0b1111).is_empty());
}

#[test]
fn a_member_stays_dirty_until_its_own_barrier_succeeded() {
    let mut d = DirtyDevices::new();
    d.mark(2);
    d.mark(5);
    assert!(d.is_dirty(2) && d.is_dirty(5) && !d.is_dirty(1));
    d.clear(2);
    assert!(!d.is_dirty(2) && d.is_dirty(5));
}

#[test]
fn a_volume_wider_than_the_mask_treats_every_member_as_dirty() {
    // The fallback costs barriers and cannot lose one, which is the only safe
    // direction for a set that cannot be represented.
    let mut d = DirtyDevices::new();
    d.mark(64);
    assert_eq!(d.mask(), u64::MAX);
}

// ---- the order, at a medium ----

#[test]
fn a_checkpoint_fences_the_medium_before_the_commit_block_and_after_it() {
    let mut v = cached(Options::defaults());
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.source_ref().forget_commands();
    v.commit().unwrap();
    let log = cmds(&v);
    // The pack's last block is the commit block. Everything before it is pack
    // body; the barrier must sit between the two, and a second must follow the
    // commit block, because this medium has no forced-unit-access of its own.
    let last_flush = log.iter().rposition(|c| *c == Cmd::Flush).expect("a barrier is owed");
    assert_eq!(last_flush, log.len() - 1, "the commit block is written through the cache");
    let fence = log[..last_flush].iter().rposition(|c| *c == Cmd::Flush)
        .expect("the commit block is preceded by a barrier");
    assert!(matches!(log[fence + 1], Cmd::Write(_)),
            "the barrier immediately precedes the block it commits");
    assert_eq!(log[fence + 1..last_flush].len(), 1,
               "exactly one block — the commit block — sits inside the fence");
    assert!(log[..fence].iter().any(|c| matches!(c, Cmd::Write(_))),
            "the pack body is written before the fence, not after");
}

#[test]
fn a_nobarrier_mount_writes_the_whole_pack_with_no_barrier_at_all() {
    let mut o = Options::defaults();
    o.barrier = false;
    let mut v = cached(o);
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.source_ref().forget_commands();
    v.commit().unwrap();
    assert!(!cmds(&v).iter().any(|c| *c == Cmd::Flush),
            "the mount said it accepts the risk; nothing may fence anyway");
}

// ---- a volume spread over members ----

/// A volume over two members, both behaving as devices with a volatile cache.
fn spread_cached(opts: Options) -> Volume<crate::devices::DeviceSet<MemImage>> {
    spread_cached_over(&[("/dev/a", 8), ("/dev/b", 7)], opts)
}

/// The same over named members.
fn spread_cached_over(devs: &[(&str, u32)], opts: Options)
    -> Volume<crate::devices::DeviceSet<MemImage>> {
    let b = test_image::with_root().devices(devs);
    let (media, table) = test_image::spread::members(b);
    let media: alloc::vec::Vec<MemImage> =
        media.into_iter().map(|m| m.with_write_cache()).collect();
    let set = crate::devices::DeviceSet::new(media, table).unwrap();
    *Volume::mount_devices(set, opts, true, &[]).unwrap()
}

/// How many barriers member `i` was asked for.
fn barriers(v: &Volume<crate::devices::DeviceSet<MemImage>>, i: usize) -> usize {
    v.source_ref().members()[i].commands().iter().filter(|c| **c == Cmd::Flush).count()
}

#[test]
fn every_member_the_pack_depends_on_is_fenced_and_the_pack_carrier_is_not() {
    // The bits are lowered only by a barrier that succeeded, so what is left
    // standing afterwards says exactly which members were skipped. Member zero
    // is skipped on purpose — its ordering is the commit block's — and every
    // other member the pack refers to must be gone from the set.
    let mut v = spread_cached(Options::defaults());
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let far = v.devices().get(1).unwrap().start_blk;
    v.write_block(far, &alloc::vec![9u8; crate::uapi::BLKSIZE]).unwrap();
    v.commit().unwrap();
    let left = v.dirty_devs.get();
    assert!(!left.is_dirty(1), "a member the pack names was committed over unfenced");
    assert!(left.is_dirty(0), "member zero is left to its commit block, not fenced twice");
}

#[test]
fn a_nobarrier_mount_leaves_every_member_unfenced_and_still_dirty() {
    let mut o = Options::defaults();
    o.barrier = false;
    let mut v = spread_cached(o);
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let far = v.devices().get(1).unwrap().start_blk;
    v.write_block(far, &alloc::vec![9u8; crate::uapi::BLKSIZE]).unwrap();
    v.commit().unwrap();
    assert!(v.dirty_devs.get().is_dirty(1), "the mount asked for no barriers; none may be issued");
    assert_eq!(barriers(&v, 1), 0);
}

#[test]
fn a_member_that_was_written_to_is_fenced_before_the_pack_commits() {
    let mut v = spread_cached(Options::defaults());
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let far = v.devices().get(1).unwrap().start_blk;
    v.write_block(far, &alloc::vec![9u8; crate::uapi::BLKSIZE]).unwrap();
    for m in v.source_ref().members() { m.forget_commands(); }
    v.commit().unwrap();
    assert_eq!(barriers(&v, 1), 1,
               "the pack names blocks on this member; its cache must be emptied ONCE, before it");
}

#[test]
fn the_member_carrying_the_pack_is_fenced_by_the_commit_block_and_not_twice() {
    let mut v = spread_cached(Options::defaults());
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let far = v.devices().get(1).unwrap().start_blk;
    v.write_block(far, &alloc::vec![9u8; crate::uapi::BLKSIZE]).unwrap();
    for m in v.source_ref().members() { m.forget_commands(); }
    v.commit().unwrap();
    // The commit block's own promise accounts for both: its pre-flush, and the
    // flush standing in for the forced-unit-access this medium lacks.
    assert_eq!(barriers(&v, 0), 2,
               "member zero is fenced by its commit block alone, not by the device pass too");
}

#[test]
fn a_nobarrier_spread_mount_fences_no_member() {
    let mut o = Options::defaults();
    o.barrier = false;
    let mut v = spread_cached(o);
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let far = v.devices().get(1).unwrap().start_blk;
    v.write_block(far, &alloc::vec![9u8; crate::uapi::BLKSIZE]).unwrap();
    for m in v.source_ref().members() { m.forget_commands(); }
    v.commit().unwrap();
    assert_eq!(barriers(&v, 0) + barriers(&v, 1), 0);
}

/// A cached-medium mount whose one file is fully checkpointed and then dirtied
/// again — the state in which `fsync` takes the CHAIN path, which is the only
/// path that owes a barrier of its own.
fn dirtied(opts: Options) -> (Volume<MemImage>, u32) {
    let mut v = cached(opts);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, b"payload").unwrap();
    v.sync_data().unwrap();
    v.commit().unwrap();
    v.write_file(ino, 0, b"x").unwrap();
    v.sync_data().unwrap();
    v.source_ref().forget_commands();
    (v, ino)
}

#[test]
fn an_fsync_that_wrote_a_chain_fences_the_medium_after_it() {
    let (mut v, ino) = dirtied(Options::defaults());
    let reason = v.fsync(ino).unwrap();
    assert!(!reason.needed(), "this fixture must take the CHAIN path, not a checkpoint");
    let log = cmds(&v);
    assert_eq!(log.last(), Some(&Cmd::Flush),
               "the chain is worthless until the device has it on the medium");
    assert!(log.iter().any(|c| matches!(c, Cmd::Write(_))), "the chain was written");
}

#[test]
fn an_fsync_under_fsync_mode_nobarrier_writes_the_chain_and_fences_nothing() {
    let mut o = Options::defaults();
    o.fsync_mode = FsyncMode::Nobarrier;
    let (mut v, ino) = dirtied(o);
    v.fsync(ino).unwrap();
    let log = cmds(&v);
    assert!(log.iter().any(|c| matches!(c, Cmd::Write(_))), "the chain is still written");
    assert!(!log.iter().any(|c| *c == Cmd::Flush));
}

#[test]
fn an_uncached_medium_is_asked_for_no_barrier_by_either_path() {
    // The same code, over a medium that reports no volatile cache: the promise
    // is already true, so keeping it must cost nothing.
    let mut v: Volume<MemImage> = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, b"payload").unwrap();
    v.sync_data().unwrap();
    v.commit().unwrap();
    v.write_file(ino, 0, b"x").unwrap();
    v.sync_data().unwrap();
    v.source_ref().forget_commands();
    v.fsync(ino).unwrap();
    v.commit().unwrap();
    assert!(!cmds(&v).iter().any(|c| *c == Cmd::Flush));
}

// ---- a page rewritten IN PLACE ----
//
// The state a build without a record of it gets silently wrong: the rewrite
// leaves the file's recorded shape untouched, so every comparison says nothing
// changed, and an `fsync` that keys on that writes nothing and fences nothing
// while the new bytes sit in the device's cache.

#[test]
fn a_clean_file_with_no_rewrite_in_place_owes_nothing() {
    assert_eq!(sync_work(false, false), SyncWork::Nothing);
}

#[test]
fn a_clean_file_with_a_rewrite_in_place_owes_a_barrier_and_no_chain() {
    assert_eq!(sync_work(false, true), SyncWork::BarrierOnly);
}

#[test]
fn a_file_that_changed_takes_the_whole_ladder_however_it_was_written() {
    assert_eq!(sync_work(true, false), SyncWork::Full);
    assert_eq!(sync_work(true, true), SyncWork::Full);
}

#[test]
fn the_record_is_per_file_and_survives_until_a_barrier_retires_it() {
    let mut u = UpdateWrites::new();
    u.record(7);
    assert!(u.owed(7) && !u.owed(8), "one file's rewrite is not another's debt");
    u.record(8);
    u.fenced(7);
    assert!(!u.owed(7) && u.owed(8));
    u.fenced_all();
    assert!(u.is_empty());
}

/// A mount whose one file has been checkpointed and then REWRITTEN IN PLACE:
/// the bytes changed, nothing about the file's shape did.
fn rewritten_in_place(opts: Options) -> (Volume<MemImage>, u32) {
    let mut v = cached(opts);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &alloc::vec![7u8; crate::uapi::BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.commit().unwrap();
    v.write_file(ino, 0, b"x").unwrap();
    v.sync_data().unwrap();
    assert!(v.inode_dirty(ino).unwrap().clean(),
            "fixture must produce the invisible case: the file compares unchanged");
    assert!(v.owes_inplace_barrier(ino), "the rewrite in place must have been recorded");
    v.source_ref().forget_commands();
    (v, ino)
}

#[test]
fn an_fsync_after_a_rewrite_in_place_fences_the_medium_and_writes_nothing() {
    let (mut v, ino) = rewritten_in_place(Options::defaults());
    assert!(!v.fsync(ino).unwrap().needed());
    // Exactly a barrier: there is nothing for a recovery chain to say about a
    // block the checkpoint already names, and the bytes are durable only once
    // the cache is empty.
    assert_eq!(cmds(&v), alloc::vec![Cmd::Flush],
               "an fsync over a rewrite in place must fence, and must not write a chain");
    assert!(!v.owes_inplace_barrier(ino), "a barrier that was issued retires the debt");
}

#[test]
fn a_skipped_barrier_leaves_the_debt_standing_for_the_next_fsync() {
    // `fsync_mode=nobarrier` asks for the barrier to be skipped, not for the
    // bytes to be forgotten: a later call that CAN pay must still know it is
    // owed, or the debt disappears with nothing having made the bytes durable.
    let mut o = Options::defaults();
    o.fsync_mode = FsyncMode::Nobarrier;
    let (mut v, ino) = rewritten_in_place(o);
    v.fsync(ino).unwrap();
    assert!(cmds(&v).is_empty());
    assert!(v.owes_inplace_barrier(ino), "a barrier nobody issued retires nothing");
}

#[test]
fn a_checkpoints_commit_block_retires_every_rewrite_in_place() {
    // The commit block's pre-flush put everything written before it on the
    // medium, so no file is still owed one on its account — and the next
    // `fsync` over an unchanged file must therefore cost nothing at all.
    let (mut v, ino) = rewritten_in_place(Options::defaults());
    v.create(ROOT_INO, b"g", &spec(), None).unwrap();
    v.commit().unwrap();
    assert!(!v.owes_inplace_barrier(ino));
    v.source_ref().forget_commands();
    v.fsync(ino).unwrap();
    assert!(cmds(&v).is_empty(), "a file the checkpoint already fenced owes nothing");
}

#[test]
fn a_nobarrier_mounts_checkpoint_retires_nothing_because_it_fenced_nothing() {
    let mut o = Options::defaults();
    o.barrier = false;
    let (mut v, ino) = rewritten_in_place(o);
    v.create(ROOT_INO, b"g", &spec(), None).unwrap();
    v.commit().unwrap();
    assert!(v.owes_inplace_barrier(ino),
            "the commit block was written plain; it made no bytes durable");
}
