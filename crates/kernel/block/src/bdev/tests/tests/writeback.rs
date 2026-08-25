use super::*;

struct DeferredDisk {
    inner: Arc<MemDisk<InodeClass>>,
    held: Spinlock<Vec<(BlockRequest, BlockCompletion)>, InodeClass>,
}
impl DeferredDisk {
    fn new(blocks: u64) -> Arc<Self> {
        Arc::new(Self { inner: MemDisk::<InodeClass>::new(BS, blocks), held: Spinlock::new(Vec::new()) })
    }
    fn complete_all(&self) {
        let held: Vec<(BlockRequest, BlockCompletion)> = core::mem::take(&mut *self.held.lock());
        for (mut req, done) in held { let r = self.inner.submit_sync(&mut req); done(req, r); }
    }
}
impl BlockDevice for DeferredDisk {
    fn block_size(&self) -> u32 { BS }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn submit(&self, request: BlockRequest, completion: BlockCompletion) { self.held.lock().push((request, completion)); }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> { self.inner.submit_sync(req) }
    fn flush(&self) -> KResult<()> { Ok(()) }
}

#[test]
fn submit_half_starts_io_and_the_page_stays_under_writeback() {
    let dev = DeferredDisk::new(64);
    let m = mapping_over(dev.clone());
    m.write_at(0, &[0x11; 64]).unwrap();
    m.fdatawrite();
    assert_eq!(m.writeback_pages(), 1);
    assert_eq!(m.dirty_pages(), 0);
    assert!(on_medium(dev.inner.as_ref(), 0, 64).iter().all(|&b| b == 0));
    dev.complete_all();
    assert_eq!(m.writeback_pages(), 0);
    assert_eq!(m.fdatawait_keep_errors(), 0);
    assert_eq!(on_medium(dev.inner.as_ref(), 0, 64), vec![0x11; 64]);
}

#[test]
fn wait_half_does_not_finish_before_deferred_writeback_completes() {
    let dev = DeferredDisk::new(64);
    let mapping = mapping_over(dev.clone());
    mapping.write_at(0, &[0x3C; 64]).unwrap();
    mapping.fdatawrite();
    let started = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let wait_mapping = Arc::clone(&mapping);
    let wait_started = Arc::clone(&started);
    let wait_done = Arc::clone(&done);
    let waiter = std::thread::spawn(move || {
        wait_started.store(true, Ordering::Release);
        assert_eq!(wait_mapping.fdatawait_keep_errors(), 0);
        wait_done.store(true, Ordering::Release);
    });
    while !started.load(Ordering::Acquire) { std::thread::yield_now(); }
    for _ in 0..1_024 { std::thread::yield_now(); }
    assert!(!done.load(Ordering::Acquire));
    dev.complete_all();
    waiter.join().unwrap();
    assert!(done.load(Ordering::Acquire));
}

struct FailingDisk { blocks: u64, fail: AtomicBool }
impl BlockDevice for FailingDisk {
    fn block_size(&self) -> u32 { BS }
    fn capacity_blocks(&self) -> u64 { self.blocks }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        if req.op == crate::BlockOp::Write && self.fail.load(Ordering::Acquire) { return Err(BlockError::Eio); }
        if req.op == crate::BlockOp::Read { for b in req.buffer.iter_mut() { *b = 0; } }
        Ok(())
    }
    fn flush(&self) -> KResult<()> { Ok(()) }
}

#[test]
fn failed_writeback_latches_an_error_the_wait_half_keeps() {
    let dev = Arc::new(FailingDisk { blocks: 64, fail: AtomicBool::new(true) });
    let m = mapping_over(dev.clone());
    m.write_at(0, &[0x22; 64]).unwrap();
    m.fdatawrite();
    assert_eq!(m.dirty_pages(), 1);
    assert_eq!(m.fdatawait_keep_errors(), BlockError::Eio as i32);
    assert_eq!(m.fdatawait_keep_errors(), BlockError::Eio as i32);
    dev.fail.store(false, Ordering::Release);
    assert_eq!(m.write_and_wait(), Err(BlockError::Eio));
    assert_eq!(m.write_and_wait(), Ok(()));
}
