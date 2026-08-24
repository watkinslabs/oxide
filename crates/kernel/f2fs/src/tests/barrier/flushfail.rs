//! A member that REFUSES to empty its cache, during a checkpoint.
//!
//! The escalation this covers is the one a fixture that always succeeds cannot
//! reach: the pack about to be written names blocks on a member whose cache
//! never got to the medium, so a filesystem that wrote it anyway would record a
//! state the volume does not hold. Both halves are asserted — the retry, which
//! is why a transient refusal costs nothing, and the stop, which is why a
//! permanent one does not become a lie on the medium.

use alloc::vec::Vec;

use sectors::source::Cmd;
use sectors::MemImage;

use crate::devices::barrier::FLUSH_RETRIES;
use crate::devices::DeviceSet;
use crate::errrec::StopReason;
use crate::flags::CP_ERROR_FLAG;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 0);

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

/// A two-member volume whose SECOND member refuses its next `refuse` barriers.
///
/// The second, because member zero carries the pack and is fenced by its own
/// commit block rather than by the device pass this is about.
fn spread_refusing(refuse: u32) -> Volume<DeviceSet<MemImage>> {
    let b = test_image::with_root().devices(&[("/dev/a", 9), ("/dev/b", 6)]);
    let (media, table) = test_image::spread::members(b);
    let media: Vec<MemImage> = media.into_iter().enumerate()
        .map(|(i, m)| {
            let m = m.with_write_cache();
            if i == 1 { m.refusing_flushes(refuse) } else { m }
        })
        .collect();
    let set = DeviceSet::new(media, table).unwrap();
    *Volume::mount_devices(set, Options::defaults(), true, &[]).unwrap()
}

/// Dirty the far member, so the checkpoint's pass has it as a target.
fn dirty_the_far_member(v: &mut Volume<DeviceSet<MemImage>>) {
    v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let far = v.devices().get(1).unwrap().start_blk;
    v.write_block(far, &alloc::vec![9u8; crate::uapi::BLKSIZE]).unwrap();
    for m in v.source_ref().members() { m.forget_commands(); }
}

fn barriers(v: &Volume<DeviceSet<MemImage>>, i: usize) -> usize {
    v.source_ref().members()[i].commands().iter().filter(|c| **c == Cmd::Flush).count()
}

/// A transient refusal costs a retry and nothing else: the checkpoint lands,
/// the member's bit is lowered, and the volume is not stopped.
#[test]
fn a_transient_refusal_is_retried_and_the_checkpoint_still_lands() {
    let mut v = spread_refusing(FLUSH_RETRIES - 1);
    dirty_the_far_member(&mut v);
    v.commit().expect("a member that came back must not fail the checkpoint");
    assert_eq!(barriers(&v, 1), (FLUSH_RETRIES - 1) as usize + 1,
               "the refusals were not all retried");
    assert!(!v.dirty_devs.get().is_dirty(1), "the bit is lowered only by a barrier that worked");
    assert_eq!(v.error_record().stops(StopReason::FlushFail), 0, "nothing was owed a stop");
    assert_eq!(v.checkpoint().flags & CP_ERROR_FLAG, 0);
}

/// A member that keeps refusing stops the checkpoint, with the reason recorded:
/// the pack names blocks whose bytes are still in a cache, so writing it would
/// describe a state the medium does not hold.
#[test]
fn a_member_that_keeps_refusing_stops_the_checkpoint() {
    let mut v = spread_refusing(u32::MAX);
    dirty_the_far_member(&mut v);
    assert!(v.commit().is_err(), "the pack was committed over an unfenced member");
    assert_eq!(barriers(&v, 1), FLUSH_RETRIES as usize,
               "the barrier was not retried exactly as many times as the policy allows");
    assert_eq!(v.error_record().stops(StopReason::FlushFail), 1,
               "the stop reason was not recorded");
    assert_ne!(v.checkpoint().flags & CP_ERROR_FLAG, 0, "the volume did not stop checkpointing");
    assert!(v.dirty_devs.get().is_dirty(1), "a failed barrier may not lower the member's bit");
}

// ---- what ONE FILE's fsync fences -----------------------------------------

/// A file whose blocks are all on one member owes ONE barrier, not one per
/// member.
///
/// The saving is the property: a barrier is a whole-cache operation, so on a
/// wide volume the difference between "the members this file is on" and "every
/// member" is real cost paid on every `fsync`.
#[test]
fn an_fsync_fences_only_the_members_the_files_blocks_landed_on() {
    let mut v = spread_refusing(0);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    // A WHOLE block, so the file has a data block of its own: a few bytes live
    // inside the inode, and such a file has no data member to record.
    v.write_file(ino, 0, &alloc::vec![0xA1u8; crate::uapi::BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.commit().unwrap();
    // Which member this file is on is the volume's choice, so it is READ rather
    // than assumed — what is asserted is that the other members are not fenced.
    //
    // The rewrite is forced OUT of place, so the record has to come from the
    // data writer itself: a build that recorded only its node writes would name
    // the node's member and leave the file's bytes in another member's cache.
    v.set_ipu_policy(crate::place::bits::DISABLE).unwrap();
    v.write_file(ino, 0, &alloc::vec![0xB2u8; crate::uapi::BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    let mask = v.dirty_ino_devs.mask(ino);
    assert!(mask != 0, "nothing was recorded for a file that has been written");
    // The record must cover BOTH owners: the member the DATA landed on, not
    // only the one its inode node did. A build that recorded node writes alone
    // would leave the file's bytes in another member's cache.
    let data_at = v.holder_addr(ino, crate::volume::Holder::Inode, 0).unwrap();
    let (data_member, _) = v.devices().target(data_at);
    let node_at = v.node_addr(ino).unwrap();
    let (node_member, _) = v.devices().target(node_at);
    assert_ne!(data_member, node_member,
               "fixture must put file data and its inode node on different members: data={data_at} node={node_at}");
    let expected = (1u64 << data_member) | (1u64 << node_member);
    assert_eq!(mask, expected,
               "the data and node members were not both recorded: data={data_member} node={node_member} mask={mask:#x}");
    for m in v.source_ref().members() { m.forget_commands(); }
    v.fsync(ino).unwrap();
    for i in 0..2usize {
        let want = if mask & (1 << i) != 0 { 1 } else { 0 };
        assert_eq!(barriers(&v, i), want,
                   "member {i}: fenced {} times for a file with mask {mask:#x}",
                   barriers(&v, i));
    }
    assert_eq!(v.dirty_ino_devs.mask(ino), 0, "the barrier did not retire the record");

    // And again for a rewrite that lands back IN place, which is a different
    // writer and which changes nothing about the file's recorded shape — so
    // nothing else in the filesystem could afterwards say which member holds it.
    v.set_ipu_policy(crate::place::bits::bit(crate::place::bits::FORCE)).unwrap();
    let at = v.holder_addr(ino, crate::volume::Holder::Inode, 0).unwrap();
    v.write_file(ino, 0, &alloc::vec![0xC3u8; crate::uapi::BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    assert_eq!(v.holder_addr(ino, crate::volume::Holder::Inode, 0).unwrap(), at,
               "the rewrite moved, so this case is not about the in-place writer");
    let (m, _) = v.devices().target(at);
    assert!(v.dirty_ino_devs.mask(ino) & (1 << m) != 0,
            "an in-place rewrite on member {m} was not recorded");
}

/// A file nothing is recorded against is fenced everywhere: a caller that
/// cannot tell "nothing written" from "not recorded" must not skip a barrier it
/// may owe.
#[test]
fn a_file_with_nothing_recorded_is_fenced_everywhere() {
    use crate::devices::barrier::fsync_flush_targets;
    assert_eq!(fsync_flush_targets(2, 0).iter().count(), 2);
    assert_eq!(fsync_flush_targets(6, 0).iter().count(), 6);
    // A volume of one carries everything, so there is nothing to narrow.
    assert_eq!(fsync_flush_targets(1, 0).iter().count(), 1);
    assert_eq!(fsync_flush_targets(1, 0b10).iter().count(), 1);
    // And a recorded mask is honoured, bounded by the members that exist.
    assert_eq!(fsync_flush_targets(4, 0b1010).iter().collect::<Vec<_>>(), [1, 3]);
    assert_eq!(fsync_flush_targets(2, 0b1010).iter().collect::<Vec<_>>(), [1]);
}

/// A checkpoint fences everything at once, so every file's record is retired.
#[test]
fn a_checkpoint_retires_every_files_record() {
    let mut v = spread_refusing(0);
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, b"payload").unwrap();
    v.sync_data().unwrap();
    assert!(!v.dirty_ino_devs.is_empty(), "nothing was recorded");
    v.commit().unwrap();
    assert!(v.dirty_ino_devs.is_empty(), "a checkpoint left records standing");
}
