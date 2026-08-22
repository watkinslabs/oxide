use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::Inode as InodeClass;

use crate::blockdev::{BlockDevice, BlockRequest, MemDisk};
use crate::types::KResult;

struct CountFlush {
    inner: Arc<MemDisk<InodeClass>>,
    flushes: AtomicU64,
}

impl CountFlush {
    fn new() -> Arc<Self> {
        Arc::new(Self { inner: MemDisk::new(512, 16), flushes: AtomicU64::new(0) })
    }
}

impl BlockDevice for CountFlush {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> { self.inner.submit_sync(req) }
    fn flush(&self) -> KResult<()> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        self.inner.flush()
    }
}

#[test]
fn the_device_half_of_sync_writes_pages_without_a_cache_barrier() {
    let raw = CountFlush::new();
    let idx = crate::registry::register("b2408", raw.clone());
    let devt = crate::registry::dev_t_of("b2408", idx).expect("registered device number");
    assert!(crate::registry::open_by_dev(devt));
    let disk = crate::registry::by_dev(devt).expect("registered disk");
    disk.mapping.write_at(0, &[0xA5; 512]).expect("dirty device page");
    super::sync::sync_bdevs(false);
    super::sync::sync_bdevs(true);
    assert_eq!(raw.flushes.load(Ordering::Relaxed), 0,
        "filesystem sync owns its barrier; the device pass owns only page writeback");
    crate::registry::close_by_dev(devt);
    crate::registry::unregister("b2408");
}
