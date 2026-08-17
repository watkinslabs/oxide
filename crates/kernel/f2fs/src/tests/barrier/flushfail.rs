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
    let b = test_image::with_root().devices(&[("/dev/a", 8), ("/dev/b", 7)]);
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
