//! The decision, and the ORDER the commands are issued in.
//!
//! The order assertions are the point. A pre-flush issued after the write it
//! was meant to precede satisfies every count-based check — one flush, one
//! write — and leaves the volume corruptible by a power cut, so the fixture
//! records a SEQUENCE and the tests compare against it position by position.

use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::Spinlock;

use crate::blockdev::{BlockDevice, BlockRequest};
use crate::queue_limits::{QueueFeatures, QueueLimits};
use crate::types::KResult;

use super::submit::{issue_flush, submit_durable};
use super::*;

/// One command the fixture device was asked for, in arrival order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cmd {
    /// A cache flush.
    Flush,
    /// A write of `len_blocks` at a block address, with what was left of the
    /// durability promise for the driver to see.
    Write(u64, bool),
}

struct Recorder {
    log: Spinlock<Vec<Cmd>, sync::TaskList>,
    features: QueueFeatures,
}

impl Recorder {
    fn new(features: QueueFeatures) -> Arc<Self> {
        Arc::new(Self { log: Spinlock::new(Vec::new()), features })
    }

    fn log(&self) -> Vec<Cmd> { self.log.lock().clone() }
}

impl BlockDevice for Recorder {
    fn block_size(&self) -> u32 { 512 }
    fn capacity_blocks(&self) -> u64 { 4096 }

    fn queue_limits(&self) -> KResult<QueueLimits> {
        Ok(QueueLimits::for_logical_block_size(512)?.with_features(self.features))
    }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        self.log.lock().push(Cmd::Write(req.start_block, req.durability.contains(FUA)));
        Ok(())
    }

    fn flush(&self) -> KResult<()> {
        self.log.lock().push(Cmd::Flush);
        Ok(())
    }
}

fn write(addr: u64, d: Durability) -> BlockRequest {
    BlockRequest::new_write(addr, 1, alloc::vec![0u8; 512]).with_durability(d)
}

#[test]
fn a_device_with_no_volatile_cache_needs_no_flush_for_either_promise() {
    let s = sequence(false, false, PREFLUSH | FUA, true);
    assert_eq!(s, Sequence { preflush: false, data: true, postflush: false, fua: false });
}

#[test]
fn a_cached_device_gets_the_preflush_it_was_asked_for() {
    let s = sequence(true, false, PREFLUSH, true);
    assert!(s.preflush && s.data && !s.postflush && !s.fua);
}

#[test]
fn forced_unit_access_becomes_a_flush_after_the_write_when_hardware_lacks_it() {
    let s = sequence(true, false, FUA, true);
    assert!(!s.preflush && s.data && s.postflush && !s.fua);
}

#[test]
fn hardware_forced_unit_access_replaces_the_flush_rather_than_adding_to_it() {
    let s = sequence(true, true, FUA, true);
    assert!(s.postflush == false && s.fua);
    assert_eq!(residue(s), FUA);
}

#[test]
fn a_cache_flush_at_a_device_without_one_decomposes_to_nothing() {
    assert!(sequence(false, false, PREFLUSH, false).is_noop());
    assert!(!sequence(true, false, PREFLUSH, false).is_noop());
}

#[test]
fn the_preflush_is_stripped_before_the_driver_sees_the_request() {
    let s = sequence(true, false, PREFLUSH | FUA, true);
    assert_eq!(residue(s), Durability::NONE, "neither promise may reach a driver that cannot keep it");
}

// The ORDER, at a real device. A pre-flush that ran after the write would pass
// every count assertion above and lose the guarantee entirely.
#[test]
fn a_commit_record_flushes_then_writes_then_flushes_again_in_that_order() {
    let d = Recorder::new(QueueFeatures::WRITE_CACHE);
    let mut req = write(7, PREFLUSH | FUA);
    submit_durable(&*d, &mut req).unwrap();
    assert_eq!(d.log(), alloc::vec![Cmd::Flush, Cmd::Write(7, false), Cmd::Flush]);
}

#[test]
fn a_preflush_only_write_issues_exactly_one_flush_and_it_comes_first() {
    let d = Recorder::new(QueueFeatures::WRITE_CACHE);
    let mut req = write(3, PREFLUSH);
    submit_durable(&*d, &mut req).unwrap();
    assert_eq!(d.log(), alloc::vec![Cmd::Flush, Cmd::Write(3, false)]);
}

#[test]
fn a_hardware_fua_device_writes_once_with_the_bit_and_no_trailing_flush() {
    let d = Recorder::new(QueueFeatures::WRITE_CACHE | QueueFeatures::FUA);
    let mut req = write(9, PREFLUSH | FUA);
    submit_durable(&*d, &mut req).unwrap();
    assert_eq!(d.log(), alloc::vec![Cmd::Flush, Cmd::Write(9, true)]);
}

#[test]
fn an_uncached_device_writes_once_and_is_asked_for_no_flush_at_all() {
    let d = Recorder::new(QueueFeatures::empty());
    let mut req = write(1, PREFLUSH | FUA);
    submit_durable(&*d, &mut req).unwrap();
    assert_eq!(d.log(), alloc::vec![Cmd::Write(1, false)]);
}

#[test]
fn an_ordinary_write_reaches_the_device_untouched() {
    let d = Recorder::new(QueueFeatures::WRITE_CACHE);
    let mut req = write(2, Durability::NONE);
    submit_durable(&*d, &mut req).unwrap();
    assert_eq!(d.log(), alloc::vec![Cmd::Write(2, false)]);
}

#[test]
fn issuing_a_bare_flush_reaches_a_cached_device_and_skips_an_uncached_one() {
    let cached = Recorder::new(QueueFeatures::WRITE_CACHE);
    issue_flush(&*cached).unwrap();
    assert_eq!(cached.log(), alloc::vec![Cmd::Flush]);
    let plain = Recorder::new(QueueFeatures::empty());
    issue_flush(&*plain).unwrap();
    assert!(plain.log().is_empty());
}

#[test]
fn a_device_that_cannot_report_its_topology_is_flushed_anyway() {
    struct Silent;
    impl BlockDevice for Silent {
        fn block_size(&self) -> u32 { 512 }
        fn capacity_blocks(&self) -> u64 { 1 }
        fn queue_limits(&self) -> KResult<QueueLimits> { Err(crate::types::BlockError::Eio) }
        fn submit_sync(&self, _req: &mut BlockRequest) -> KResult<()> { Ok(()) }
        fn flush(&self) -> KResult<()> { Ok(()) }
    }
    assert_eq!(super::submit::facts(&Silent), (true, false));
}

#[test]
fn the_queue_publishes_forced_unit_access_to_userspace() {
    let l = QueueLimits::for_logical_block_size(512).unwrap()
        .with_features(QueueFeatures::WRITE_CACHE | QueueFeatures::FUA);
    assert_eq!(l.sysfs_value("fua"), Some(1));
    assert!(l.write_cache() && l.fua());
    let plain = QueueLimits::for_logical_block_size(512).unwrap();
    assert_eq!(plain.sysfs_value("fua"), Some(0));
    assert!(!plain.write_cache());
}
