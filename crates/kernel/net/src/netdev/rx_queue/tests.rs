use super::*;

fn caps() -> QueueCaps {
    QueueCaps {
        queue_mgmt: true, nr_rx_queues: 4, hds: HdsConfig::Enabled,
        hds_thresh: 0, xdp_progs: 0, rx_page_size_ok: true,
    }
}

#[test]
fn a_capable_unbound_queue_is_admitted() {
    assert_eq!(admit_mp_open(&caps(), 0, false, false), Ok(()));
    assert_eq!(admit_mp_open(&caps(), 3, true, false), Ok(()));
}

#[test]
fn a_device_that_cannot_manage_its_queues_is_refused_before_anything_else() {
    let mut c = caps();
    c.queue_mgmt = false;
    // Every later rung also fails here; the answer is still the first one.
    c.nr_rx_queues = 0;
    c.hds = HdsConfig::Disabled;
    assert_eq!(admit_mp_open(&c, 9, true, true), Err(NetError::Eopnotsupp));
}

#[test]
fn a_queue_index_past_the_device_is_out_of_range() {
    assert_eq!(admit_mp_open(&caps(), 4, false, false), Err(NetError::Erange));
    assert_eq!(admit_mp_open(&caps(), u32::MAX, false, false), Err(NetError::Erange));
}

/// The range answer precedes the split answer: a caller naming a queue that
/// does not exist learns THAT, not something about a queue it never had.
#[test]
fn range_is_decided_before_header_data_split() {
    let mut c = caps();
    c.hds = HdsConfig::Disabled;
    assert_eq!(admit_mp_open(&c, 4, false, false), Err(NetError::Erange));
}

#[test]
fn a_device_without_header_data_split_is_refused() {
    for h in [HdsConfig::Unknown, HdsConfig::Disabled] {
        let mut c = caps();
        c.hds = h;
        assert_eq!(admit_mp_open(&c, 0, false, false), Err(NetError::Einval));
    }
}

#[test]
fn a_non_zero_split_threshold_is_refused() {
    let mut c = caps();
    c.hds_thresh = 1;
    assert_eq!(admit_mp_open(&c, 0, false, false), Err(NetError::Einval));
}

#[test]
fn a_program_on_the_receive_hook_is_refused_as_already_present() {
    let mut c = caps();
    c.xdp_progs = 1;
    assert_eq!(admit_mp_open(&c, 0, false, false), Err(NetError::Eexist));
}

#[test]
fn a_buffer_size_is_refused_only_when_the_device_cannot_be_told() {
    let mut c = caps();
    c.rx_page_size_ok = false;
    assert_eq!(admit_mp_open(&c, 0, false, false), Ok(()));
    assert_eq!(admit_mp_open(&c, 0, true, false), Err(NetError::Eopnotsupp));
}

#[test]
fn a_queue_that_already_has_a_provider_is_refused_last() {
    assert_eq!(admit_mp_open(&caps(), 0, false, true), Err(NetError::Eexist));
    // …and the buffer-size refusal still wins over it.
    let mut c = caps();
    c.rx_page_size_ok = false;
    assert_eq!(admit_mp_open(&c, 0, true, true), Err(NetError::Eopnotsupp));
}

#[test]
fn a_queue_array_is_never_empty_and_indexes_only_its_own_queues() {
    let qs = RxQueues::new(0);
    assert_eq!(qs.len(), 1);
    assert!(qs.get(0).is_some());
    assert!(qs.get(1).is_none());
    let qs = RxQueues::new(4);
    assert_eq!(qs.len(), 4);
    assert!(qs.get(3).is_some());
    assert!(qs.get(4).is_none());
}

// ---- the binding end to end -------------------------------------------
//
// The ladder above says which registrations are legal. These say that a legal
// one really binds: a device that CAN re-provision a queue gets a pool, the
// pool draws from the provider, and unbinding tells the provider its queue is
// gone. Without these the ladder could be perfectly correct in front of a
// binding that never happens.

use crate::page_pool::{MemoryProvider, Netmem, NetIovArea, PagePool};
use crate::{MacAddr, Pkt};
use crate::netdev::{NamespaceDropAction, NetStats};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// A device that can re-provision one receive queue and splits headers from
/// payload — the two things a memory provider needs of a driver.
struct ZcDev {
    restarts: AtomicU32,
    restart_fails: bool,
}

impl NetDev for ZcDev {
    fn name(&self) -> &str { "zc0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> NamespaceDropAction { NamespaceDropAction::Destroy }
    fn xmit(&self, _pkt: Pkt) -> NetResult<()> { Ok(()) }
    fn stats(&self) -> NetStats { NetStats::default() }
    fn rx_queue_count(&self) -> u32 { 2 }
    fn rx_queue_mgmt(&self) -> bool { true }
    fn hds_config(&self) -> HdsConfig { HdsConfig::Enabled }
    fn rx_page_size_supported(&self) -> bool { true }
    fn rx_queue_restart(&self, _idx: u32) -> NetResult<()> {
        self.restarts.fetch_add(1, Ordering::AcqRel);
        if self.restart_fails { Err(NetError::Eio) } else { Ok(()) }
    }
}

struct Prov {
    area: Arc<NetIovArea>,
    free: sync::Spinlock<Vec<u32>, sync::Socket>,
    uninstalled: AtomicBool,
}

impl Prov {
    fn new(n: u32) -> Arc<Self> {
        Arc::new(Self {
            area: Arc::new(NetIovArea::new(n as usize)),
            free: sync::Spinlock::new((0..n).rev().collect()),
            uninstalled: AtomicBool::new(false),
        })
    }
}

impl MemoryProvider for Prov {
    fn alloc_netmems(&self, _p: &PagePool, out: &mut Vec<Netmem>, to_alloc: usize) -> usize {
        let mut g = self.free.lock();
        let mut n = 0;
        while n < to_alloc {
            let Some(idx) = g.pop() else { break };
            out.push(Netmem { area: Arc::clone(&self.area), idx });
            n += 1;
        }
        n
    }
    fn release_netmem(&self, nm: &Netmem) { self.free.lock().push(nm.idx); }
    fn init(&self, _p: &PagePool) -> Result<(), NetError> { Ok(()) }
    fn destroy(&self) {}
    fn uninstall(&self) { self.uninstalled.store(true, Ordering::Release); }
    fn rx_buf_len(&self) -> u32 { 4096 }
}

fn dev(restart_fails: bool) -> Arc<dyn NetDev> {
    Arc::new(ZcDev { restarts: AtomicU32::new(0), restart_fails }) as Arc<dyn NetDev>
}

fn params(p: &Arc<Prov>, rx_page_size: u32) -> crate::page_pool::MpParams {
    crate::page_pool::MpParams { ops: Arc::clone(p) as Arc<dyn MemoryProvider>, rx_page_size }
}

#[test]
fn a_capable_device_really_binds_and_the_queue_draws_from_the_provider() {
    let d = dev(false);
    let qs = Arc::new(RxQueues::new(d.rx_queue_count()));
    let p = Prov::new(4);
    let pool = mp_open_rxq(&d, &qs, 1, &params(&p, 0)).unwrap();
    assert!(qs.get(1).unwrap().has_mp());
    assert!(!qs.get(0).unwrap().has_mp());
    // The queue's pool is the one the binding built, and it really allocates.
    assert!(Arc::ptr_eq(&qs.get(1).unwrap().pool().unwrap(), &pool));
    let nm = pool.alloc_netmem().unwrap();
    assert_eq!(nm.niov().refs(), 1);
    pool.put_netmem(&nm);
}

#[test]
fn binding_a_second_provider_to_the_same_queue_is_refused() {
    let d = dev(false);
    let qs = Arc::new(RxQueues::new(d.rx_queue_count()));
    let p = Prov::new(4);
    let q = Prov::new(4);
    mp_open_rxq(&d, &qs, 0, &params(&p, 0)).unwrap();
    assert_eq!(mp_open_rxq(&d, &qs, 0, &params(&q, 0)).err(), Some(NetError::Eexist));
}

/// A device that could not be re-provisioned must not be left claiming a
/// provider it does not draw from.
#[test]
fn a_failed_restart_leaves_the_queue_unbound() {
    let d = dev(true);
    let qs = Arc::new(RxQueues::new(d.rx_queue_count()));
    let p = Prov::new(4);
    assert_eq!(mp_open_rxq(&d, &qs, 0, &params(&p, 0)).err(), Some(NetError::Eio));
    assert!(!qs.get(0).unwrap().has_mp());
}

#[test]
fn closing_a_binding_clears_the_queue_and_tells_the_provider() {
    let d = dev(false);
    let qs = Arc::new(RxQueues::new(d.rx_queue_count()));
    let p = Prov::new(4);
    let mp = params(&p, 0);
    mp_open_rxq(&d, &qs, 0, &mp).unwrap();
    mp_close_rxq(&d, &qs, 0, &mp);
    assert!(!qs.get(0).unwrap().has_mp());
    assert!(p.uninstalled.load(Ordering::Acquire));
}

/// A close naming a DIFFERENT provider must leave the queue alone: a binder
/// that raced a teardown could otherwise clear a binding somebody else made.
#[test]
fn closing_with_the_wrong_provider_leaves_the_binding_alone() {
    let d = dev(false);
    let qs = Arc::new(RxQueues::new(d.rx_queue_count()));
    let p = Prov::new(4);
    let other = Prov::new(4);
    mp_open_rxq(&d, &qs, 0, &params(&p, 0)).unwrap();
    mp_close_rxq(&d, &qs, 0, &params(&other, 0));
    assert!(qs.get(0).unwrap().has_mp());
    assert!(!p.uninstalled.load(Ordering::Acquire));
}

/// A device going away tells every bound provider, rather than leaving it
/// waiting for buffers a queue that no longer exists will never return.
#[test]
fn a_device_teardown_uninstalls_every_binding() {
    let d = dev(false);
    let qs = Arc::new(RxQueues::new(d.rx_queue_count()));
    let a = Prov::new(4);
    let b = Prov::new(4);
    mp_open_rxq(&d, &qs, 0, &params(&a, 0)).unwrap();
    mp_open_rxq(&d, &qs, 1, &params(&b, 0)).unwrap();
    uninstall_all(&qs);
    assert!(a.uninstalled.load(Ordering::Acquire));
    assert!(b.uninstalled.load(Ordering::Acquire));
    assert!(!qs.get(0).unwrap().has_mp());
    assert!(!qs.get(1).unwrap().has_mp());
}

/// The buffer size the binding asked for reaches the pool, which is the whole
/// point of asking: a device told 16 KiB and a pool handing out 4 KiB would
/// have the device write past a buffer's end.
#[test]
fn a_requested_buffer_size_reaches_the_pool() {
    let d = dev(false);
    let qs = Arc::new(RxQueues::new(d.rx_queue_count()));
    let p = Prov::new(4);
    let pool = mp_open_rxq(&d, &qs, 0, &params(&p, 16384)).unwrap();
    assert_eq!(pool.buf_len(), 16384);
}
