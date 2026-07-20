use super::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use ::core::sync::atomic::{AtomicBool, Ordering};
use crate::{BlockCompletion, BlockDevice, BlockError, BlockRequest, KResult, MemDisk};
use sync::{Spinlock, TaskList};

struct DeferredDevice {
    inner: Arc<dyn BlockDevice>,
    pending: Spinlock<Option<(BlockRequest, BlockCompletion)>, TaskList>,
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
