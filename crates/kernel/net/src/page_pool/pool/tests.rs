use super::*;
use crate::page_pool::netmem::NetIovArea;
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

/// A provider backed by a freelist over one area — the same shape a zero-copy
/// receive queue's provider has, with none of its ABI.
struct FakeProvider {
    area: Arc<NetIovArea>,
    free: Spinlock<Vec<u32>, SocketLockClass>,
    released: AtomicU32,
    destroyed: AtomicBool,
    uninstalled: AtomicBool,
    refuse_init: bool,
}

impl FakeProvider {
    fn new(n: u32, refuse_init: bool) -> Arc<Self> {
        Arc::new(Self {
            area: Arc::new(NetIovArea::new(n as usize)),
            free: Spinlock::new((0..n).rev().collect()),
            released: AtomicU32::new(0),
            destroyed: AtomicBool::new(false),
            uninstalled: AtomicBool::new(false),
            refuse_init,
        })
    }
    fn free_count(&self) -> usize { self.free.lock().len() }
}

impl MemoryProvider for FakeProvider {
    fn alloc_netmems(&self, _pool: &PagePool, out: &mut Vec<Netmem>, to_alloc: usize) -> usize {
        let mut g = self.free.lock();
        let mut n = 0;
        while n < to_alloc {
            let Some(idx) = g.pop() else { break };
            out.push(Netmem { area: Arc::clone(&self.area), idx });
            n += 1;
        }
        n
    }
    fn release_netmem(&self, nm: &Netmem) {
        self.released.fetch_add(1, Ordering::AcqRel);
        self.free.lock().push(nm.idx);
    }
    fn init(&self, _pool: &PagePool) -> Result<(), NetError> {
        if self.refuse_init { Err(NetError::Einval) } else { Ok(()) }
    }
    fn destroy(&self) { self.destroyed.store(true, Ordering::Release); }
    fn uninstall(&self) { self.uninstalled.store(true, Ordering::Release); }
    fn rx_buf_len(&self) -> u32 { 4096 }
}

fn params(p: &Arc<FakeProvider>, rx_page_size: u32) -> MpParams {
    MpParams { ops: Arc::clone(p) as Arc<dyn MemoryProvider>, rx_page_size }
}

#[test]
fn a_provider_that_refuses_init_refuses_the_pool() {
    let p = FakeProvider::new(4, true);
    assert_eq!(PagePool::create(&params(&p, 0)).err(), Some(NetError::Einval));
    assert!(!p.destroyed.load(Ordering::Acquire));
}

#[test]
fn buffer_length_comes_from_the_binding_when_it_states_one() {
    let p = FakeProvider::new(4, false);
    assert_eq!(PagePool::create(&params(&p, 0)).unwrap().buf_len(), 4096);
    assert_eq!(PagePool::create(&params(&p, 16384)).unwrap().buf_len(), 16384);
}

#[test]
fn alloc_takes_from_the_provider_and_seeds_one_reference() {
    let p = FakeProvider::new(4, false);
    let pool = PagePool::create(&params(&p, 0)).unwrap();
    let nm = pool.alloc_netmem().unwrap();
    assert_eq!(nm.niov().refs(), 1);
    // One refill drained the provider into the cache.
    assert_eq!(p.free_count(), 0);
}

#[test]
fn a_buffer_returns_to_the_provider_only_on_its_last_reference() {
    let p = FakeProvider::new(1, false);
    let pool = PagePool::create(&params(&p, 0)).unwrap();
    let nm = pool.alloc_netmem().unwrap();
    nm.niov().get();
    pool.put_netmem(&nm);
    assert_eq!(p.released.load(Ordering::Acquire), 0);
    pool.put_netmem(&nm);
    assert_eq!(p.released.load(Ordering::Acquire), 1);
}

#[test]
fn an_exhausted_provider_reports_no_buffer_rather_than_failing() {
    let p = FakeProvider::new(1, false);
    let pool = PagePool::create(&params(&p, 0)).unwrap();
    assert!(pool.alloc_netmem().is_some());
    assert!(pool.alloc_netmem().is_none());
}

#[test]
fn destroy_returns_the_cache_and_tells_the_provider() {
    let p = FakeProvider::new(8, false);
    let pool = PagePool::create(&params(&p, 0)).unwrap();
    let _nm = pool.alloc_netmem().unwrap();
    assert_eq!(p.free_count(), 0);
    pool.destroy();
    // The seven still in the cache went back; the one handed out did not.
    assert_eq!(p.free_count(), 7);
    assert!(p.destroyed.load(Ordering::Acquire));
}

#[test]
fn a_cached_buffer_is_reused_before_the_provider_is_asked_again() {
    let p = FakeProvider::new(8, false);
    let pool = PagePool::create(&params(&p, 0)).unwrap();
    let a = pool.alloc_netmem().unwrap();
    pool.put_netmem(&a);
    let before = p.released.load(Ordering::Acquire);
    let _b = pool.alloc_netmem().unwrap();
    // The second allocation came from the cache: the provider saw exactly the
    // one release and no second refill.
    assert_eq!(p.released.load(Ordering::Acquire), before);
}
