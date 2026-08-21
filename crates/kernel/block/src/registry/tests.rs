use super::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use ::core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::{BlockCompletion, BlockDevice, BlockError, BlockRequest, KResult, MemDisk, QueueFeatures, QueueLimits};
use sync::{Spinlock, TaskList};

struct DeferredDevice {
    inner: Arc<dyn BlockDevice>,
    pending: Spinlock<Option<(BlockRequest, BlockCompletion)>, TaskList>,
}

struct LimitedDiscardDevice { inner: Arc<dyn BlockDevice>, calls: AtomicU32, limits: QueueLimits }
impl LimitedDiscardDevice {
    fn new() -> Arc<Self> {
        const BLOCK_SIZE: u32 = 512;
        const DISCARD_SECTORS: u32 = 2;
        Arc::new(Self {
            inner: MemDisk::<TaskList>::new(BLOCK_SIZE, 16), calls: AtomicU32::new(0),
            limits: QueueLimits::new(BLOCK_SIZE, BLOCK_SIZE, BLOCK_SIZE, 0).unwrap()
                .with_discard(DISCARD_SECTORS, DISCARD_SECTORS, BLOCK_SIZE).unwrap()
                .with_features(QueueFeatures::STABLE_WRITES),
        })
    }
}
impl BlockDevice for LimitedDiscardDevice {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn queue_limits(&self) -> KResult<QueueLimits> { Ok(self.limits) }
    fn supports_discard(&self) -> bool { true }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn submit_sync(&self, request: &mut BlockRequest) -> KResult<()> {
        if request.op == crate::BlockOp::Discard { self.calls.fetch_add(1, Ordering::Relaxed); }
        self.inner.submit_sync(request)
    }
    fn flush(&self) -> KResult<()> { self.inner.flush() }
}

impl DeferredDevice {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: MemDisk::<TaskList>::new(512, 8),
            pending: Spinlock::new(None),
        })
    }

    fn finish(&self) {
        let Some((mut request, completion)) = self.pending.lock().take() else {
            panic!("deferred request missing");
        };
        let result = self.inner.submit_sync(&mut request);
        completion(request, result);
    }
}

impl BlockDevice for DeferredDevice {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn submit(&self, request: BlockRequest, completion: BlockCompletion) {
        let mut pending = self.pending.lock();
        assert!(pending.is_none(), "one deferred request per fixture");
        *pending = Some((request, completion));
    }
    fn submit_sync(&self, request: &mut BlockRequest) -> KResult<()> {
        self.inner.submit_sync(request)
    }
    fn flush(&self) -> KResult<()> { self.inner.flush() }
}

#[test]
fn size_units_512_block() { assert_eq!(size_512_sectors(2048, 512), 2048); }
#[test]
fn size_units_4k_block() { assert_eq!(size_512_sectors(1000, 4096), 8000); }
#[test]
fn dynamic_major_is_driver_owned_not_name_derived() {
    let a = BlockDriver::dynamic("registry-test-a");
    let b = BlockDriver::dynamic("registry-test-b");
    let an = allocate_number(a).expect("dynamic major a");
    let bn = allocate_number(b).expect("dynamic major b");
    assert_ne!(an.major, bn.major);
    assert_eq!(an.minor, 0);
    release_number(a, an); release_number(b, bn);
}

#[test]
fn published_disk_indices_do_not_reuse_a_live_disk_identity() {
    const FIRST: &str = "registry-index-first";
    const LIVE: &str = "registry-index-live";
    const LATER: &str = "registry-index-later";
    let first = register(FIRST, MemDisk::<TaskList>::new(512, 8));
    let live = register(LIVE, MemDisk::<TaskList>::new(512, 8));
    assert!(unregister(FIRST));
    let later = register(LATER, MemDisk::<TaskList>::new(512, 8));
    assert_ne!(later, live, "a new disk cannot alias a live disk's published identity");
    assert_eq!(by_index(live).as_deref().map(|disk| disk.name.as_str()), Some(LIVE));
    assert_eq!(by_index(later).as_deref().map(|disk| disk.name.as_str()), Some(LATER));
    assert!(unregister(LIVE));
    assert!(unregister(LATER));
    assert_ne!(first, live);
}

#[test]
fn released_minor_never_aliases_a_live_minor() {
    let driver = BlockDriver::dynamic("registry-live-minor");
    let first = allocate_number(driver).expect("first number");
    let live = allocate_number(driver).expect("live number");
    release_number(driver, first);
    let later = allocate_number(driver).expect("later number");
    assert_ne!(later, live, "a released tail cannot roll back over a live minor");
    release_number(driver, later);
    release_number(driver, live);
}

#[test]
fn scsi_disk_names_use_the_shared_reusable_base26_allocator() {
    let mut names = Vec::new();
    for _ in 0..27 { names.push(reserve_scsi_disk_name().expect("SCSI disk name")); }
    assert_eq!(names[0].as_str(), "sda");
    assert_eq!(names[25].as_str(), "sdz");
    assert_eq!(names[26].as_str(), "sdaa");
    drop(names.remove(0));
    assert_eq!(reserve_scsi_disk_name().expect("reused SCSI disk name").as_str(), "sda");
}

#[test]
fn holders_openers_and_quiesce_gate_are_distinct_and_atomic() {
    const NAME: &str = "registry-lifecycle";
    let dev: Arc<dyn crate::BlockDevice> = MemDisk::<TaskList>::new(512, 8);
    let index = register(NAME, dev);
    let dev_t = dev_t_of(NAME, index).expect("published dev_t");

    assert!(claim(NAME));
    assert_eq!(holder_count(NAME), Some(1));
    assert_eq!(opener_count(NAME), Some(0));
    assert!(try_quiesce(NAME).is_none(), "a holder blocks destructive lifecycle");
    assert!(release(NAME));

    assert!(open_by_dev(dev_t));
    assert_eq!(holder_count(NAME), Some(0));
    assert_eq!(opener_count(NAME), Some(1));
    assert!(try_quiesce(NAME).is_none(), "an open file blocks destructive lifecycle");
    assert!(close_by_dev(dev_t));

    let gate = try_quiesce(NAME).expect("drained disk admits exclusive lifecycle token");
    assert!(!claim(NAME), "quiesce atomically closes holder admission");
    assert!(!open_by_dev(dev_t), "quiesce atomically closes VFS opener admission");
    let disk = by_name(NAME).expect("disk remains published during reset gate");
    let mut request = BlockRequest::new_flush();
    assert_eq!(disk.dev.submit_sync(&mut request), Err(BlockError::Ebusy),
        "quiesce atomically closes generic I/O admission");
    drop(gate);
    assert!(open_by_dev(dev_t), "dropping reset token reopens admission");
    assert!(close_by_dev(dev_t));
    assert!(unregister(NAME));
}

#[test]
fn raii_target_claim_retains_canonical_device_until_drop() {
    const NAME: &str = "registry-raii-claim";
    let dev: Arc<dyn crate::BlockDevice> = MemDisk::<TaskList>::new(512, 8);
    register(NAME, dev.clone());
    let claim = claim_target(NAME).expect("published target is claimable");
    assert!(Arc::ptr_eq(&claim.device(), &by_name(NAME).unwrap().dev));
    assert_eq!(holder_count(NAME), Some(1));
    assert!(!unregister(NAME), "a live target claim blocks disappearance");
    drop(claim);
    assert_eq!(holder_count(NAME), Some(0));
    assert!(unregister(NAME));
}

#[test]
fn opener_seal_keeps_the_control_opener_and_refuses_new_opens() {
    const NAME: &str = "registry-open-seal";
    let dev: Arc<dyn crate::BlockDevice> = MemDisk::<TaskList>::new(512, 8);
    let index = register(NAME, dev);
    let dev_t = dev_t_of(NAME, index).expect("published dev_t");
    assert!(open_by_dev(dev_t), "the control file owns one opener");
    let seal = seal_openers(dev_t, 1).expect("retain that opener");
    assert_eq!(try_open_by_dev(dev_t), Err(OpenFailure::Closing));
    assert_eq!(opener_count(NAME), Some(1));
    drop(seal);
    assert!(open_by_dev(dev_t), "dropping the seal restores opener admission");
    assert!(close_by_dev(dev_t));
    assert!(close_by_dev(dev_t));
    assert!(unregister(NAME));
}

#[test]
fn controlled_removal_retains_only_the_control_opener_until_unpublish() {
    const NAME: &str = "registry-controlled-removal";
    let index = register(NAME, MemDisk::<TaskList>::new(512, 8));
    let dev_t = dev_t_of(NAME, index).expect("published dev_t");
    let disk = by_name(NAME).expect("registered disk");
    assert!(open_by_dev(dev_t), "the control file owns one opener");
    let removal = begin_controlled_removal(dev_t, 1).expect("one control opener may stop the disk");
    assert_eq!(try_open_by_dev(dev_t), Err(OpenFailure::Closing));
    assert!(!claim(NAME), "controlled removal closes new holder admission");
    assert!(removal.unregister());
    assert!(by_name(NAME).is_none(), "completed removal unpublishes the disk");
    assert_eq!(disk.opener_count(), 1, "the retained control opener remains releasable");
    assert!(close_disk(&disk));
}

#[test]
fn controlled_removal_waits_for_preexisting_submission() {
    const NAME: &str = "registry-controlled-removal-drain";
    let inner = DeferredDevice::new();
    let dev: Arc<dyn BlockDevice> = inner.clone();
    let index = register(NAME, dev);
    let dev_t = dev_t_of(NAME, index).expect("published dev_t");
    let disk = by_name(NAME).expect("registered disk");
    assert!(open_by_dev(dev_t));
    disk.dev.submit(BlockRequest::new_flush(), Box::new(|_, result| assert_eq!(result, Ok(()))));
    let removal = begin_controlled_removal(dev_t, 1).expect("control opener may begin final removal");
    let stop = std::thread::spawn(move || removal.unregister());
    let mut saw_closed_admission = false;
    for _ in 0..10_000 {
        let mut later = BlockRequest::new_flush();
        if disk.dev.submit_sync(&mut later) == Err(BlockError::Ebusy) { saw_closed_admission = true; break; }
        std::thread::yield_now();
    }
    assert!(saw_closed_admission, "final removal must wait rather than unlink a live request");
    inner.finish();
    assert!(stop.join().expect("removal thread"));
    assert!(close_disk(&disk));
}

#[test]
fn quiesce_waits_for_previously_admitted_async_submission() {
    const NAME: &str = "registry-async-lifecycle";
    let inner = DeferredDevice::new();
    let dev: Arc<dyn BlockDevice> = inner.clone();
    assert_ne!(register(NAME, dev), 0);
    let disk = by_name(NAME).expect("registered disk");
    let done = Arc::new(AtomicBool::new(false));
    let done_at_completion = Arc::clone(&done);
    disk.dev.submit(BlockRequest::new_flush(), Box::new(move |_, result| {
        assert_eq!(result, Ok(()));
        done_at_completion.store(true, Ordering::Release);
    }));
    assert!(try_quiesce(NAME).is_none(), "queued request keeps reset/remove out");
    inner.finish();
    assert!(done.load(Ordering::Acquire));
    let gate = try_quiesce(NAME).expect("completion drains canonical submission gate");
    drop(gate);
    assert!(unregister(NAME));
}

#[test]
fn reset_freeze_keeps_live_identity_and_drains_after_admission_stops() {
    const NAME: &str = "registry-live-reset";
    let inner = DeferredDevice::new();
    let dev: Arc<dyn BlockDevice> = inner.clone();
    let index = register(NAME, dev);
    let dev_t = dev_t_of(NAME, index).expect("published dev_t");
    let disk = by_name(NAME).expect("registered disk");
    assert!(claim(NAME));
    assert!(open_by_dev(dev_t));
    disk.dev.submit(BlockRequest::new_flush(), Box::new(|_, result| assert_eq!(result, Ok(()))));

    let gate = try_freeze_for_reset(NAME).expect("reset freezes a live disk with users");
    assert_eq!(holder_count(NAME), Some(1));
    assert_eq!(opener_count(NAME), Some(1));
    assert_eq!(dev_t_of(NAME, index), Some(dev_t), "reset retains the published dev_t");
    assert!(!gate.is_drained(), "the freeze observes its pre-existing request");
    let mut request = BlockRequest::new_flush();
    assert_eq!(disk.dev.submit_sync(&mut request), Err(BlockError::Ebusy), "freeze closes later I/O admission");
    assert!(try_quiesce(NAME).is_none(), "removal cannot overlap a live reset");

    inner.finish();
    assert!(gate.is_drained(), "completion drains the frozen request population");
    gate.wait_for_drain();
    drop(gate);
    assert!(close_by_dev(dev_t));
    assert!(release(NAME));
    assert!(unregister(NAME));
}

#[test]
fn reset_freeze_serializes_competing_lifecycle_owners_without_evicting_users() {
    const NAME: &str = "registry-reset-owner-contention";
    let index = register(NAME, MemDisk::<TaskList>::new(512, 8));
    let dev_t = dev_t_of(NAME, index).expect("published dev_t");
    assert!(claim(NAME));

    let reset = try_freeze_for_reset(NAME).expect("first reset owns queue freeze");
    assert!(try_freeze_for_reset(NAME).is_none(), "a second reset cannot overlap the owner");
    assert!(try_quiesce(NAME).is_none(), "destructive removal cannot overlap reset");
    assert!(open_by_dev(dev_t), "a reset preserves live VFS users");
    assert_eq!(holder_count(NAME), Some(1));
    assert_eq!(opener_count(NAME), Some(1));

    drop(reset);
    assert!(close_by_dev(dev_t));
    assert!(release(NAME));
    assert!(unregister(NAME));
}

#[test]
fn forced_detach_unlinks_immediately_and_waits_only_preexisting_io() {
    const NAME: &str = "registry-forced-detach";
    let inner = DeferredDevice::new();
    let dev: Arc<dyn BlockDevice> = inner.clone();
    let index = register(NAME, dev);
    let dev_t = dev_t_of(NAME, index).expect("published dev_t");
    let disk = by_name(NAME).expect("registered disk");
    assert!(claim(NAME));
    assert!(open_by_dev(dev_t));
    assert_eq!(disk.mapping.write_at(0, &[0x7a]), Ok(1), "fixture leaves one buffered raw write");
    disk.dev.submit(BlockRequest::new_flush(), Box::new(|_, result| assert_eq!(result, Ok(()))));

    let detach = begin_forced_detach(NAME).expect("surprise removal owns live disk");
    assert_eq!(detach.name(), NAME);
    assert!(by_name(NAME).is_none(), "new name lookups are unlinked immediately");
    assert!(by_dev(dev_t).is_none(), "new dev_t lookups are unlinked immediately");
    assert!(!claim(NAME), "new holders cannot enter a dead disk");
    assert!(!open_by_dev(dev_t), "new VFS opens cannot enter a dead disk");
    let mut later = BlockRequest::new_flush();
    assert_eq!(disk.dev.submit_sync(&mut later), Err(BlockError::Eio), "retained handles reject later I/O");
    let mut cached = [0u8; 1];
    assert_eq!(disk.mapping.read_at(0, &mut cached), Err(BlockError::Eio), "cached reads cannot outlive media");
    assert_eq!(disk.mapping.write_at(0, &[0x23]), Err(BlockError::Eio), "cached writes cannot outlive media");
    assert!(!detach.is_drained(), "the detach observes its pre-existing request");

    inner.finish();
    detach.wait_for_drain();
    assert!(detach.is_drained(), "driver DMA release follows the last admitted completion");
}

#[test]
fn registry_splits_discard_at_canonical_queue_limit() {
    const NAME: &str = "registry-discard-limit";
    const REQUEST_BLOCKS: u32 = 5;
    const EXPECTED_SUBMISSIONS: u32 = 3;
    let inner = LimitedDiscardDevice::new();
    let dev: Arc<dyn BlockDevice> = inner.clone();
    assert_ne!(register(NAME, dev), 0);
    let disk = by_name(NAME).expect("registered disk");
    let mut request = BlockRequest::new_discard(0, REQUEST_BLOCKS);
    assert_eq!(disk.dev.submit_sync(&mut request), Ok(()));
    assert_eq!(inner.calls.load(Ordering::Relaxed), EXPECTED_SUBMISSIONS);
    assert!(unregister(NAME));
}
