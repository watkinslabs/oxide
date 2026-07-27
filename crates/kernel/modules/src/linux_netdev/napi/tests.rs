use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static POLLS: AtomicUsize = AtomicUsize::new(0);

struct TestDev;

impl net::NetDev for TestDev {
    fn name(&self) -> &str { "napi-test" }
    fn mac(&self) -> net::MacAddr { net::MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, _pkt: net::Pkt) -> net::NetResult<()> { Ok(()) }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> net::NamespaceDropAction {
        net::NamespaceDropAction::Destroy
    }
}

unsafe extern "C" fn count_poll(_napi: *mut LinuxNapiStruct, _budget: i32) -> i32 {
    POLLS.fetch_add(1, Ordering::AcqRel);
    0
}

fn napi(dev: *mut LinuxNetDevice) -> LinuxNapiStruct {
    LinuxNapiStruct {
        dev,
        poll: Some(count_poll),
        weight: DEFAULT_NAPI_WEIGHT,
        state: core::sync::atomic::AtomicU32::new(0),
        rxq: 0,
        txq: 0,
        scheduled: core::sync::atomic::AtomicU32::new(0),
        ingress_generation: core::sync::atomic::AtomicU64::new(0),
    }
}

fn fixture() -> (net::NetIfaceId, *mut LinuxNetDevice) {
    let iface = net::sock::stack().ifaces.register(Arc::new(TestDev));
    // SAFETY: fixture owns the allocation until its explicit cleanup.
    let dev = unsafe { crate::linux_netdev::alloc::alloc_etherdev(0) };
    assert!(!dev.is_null());
    // SAFETY: the test exclusively owns this allocated net_device.
    unsafe { (*dev).ifindex = iface.raw(); }
    (iface, dev)
}

unsafe fn cleanup(iface: net::NetIfaceId, dev: *mut LinuxNetDevice) {
    let _ = net::sock::stack().unregister_iface(iface);
    // SAFETY: caller owns the allocation and has removed its published test iface.
    unsafe { crate::linux_netdev::alloc::free_netdev(dev); }
}

#[test]
fn current_generation_runs_poll_under_ingress_lease() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    POLLS.store(0, Ordering::Release);
    let (iface, dev) = fixture();
    let mut napi = napi(dev);

    // SAFETY: test-owned NAPI and net_device storage remain live through the calls.
    unsafe {
        assert!(napi_schedule_prep(&mut napi));
        __napi_schedule(&mut napi);
        cleanup(iface, dev);
    }
    assert_eq!(POLLS.load(Ordering::Acquire), 1);
}

#[test]
fn retired_generation_rejects_prepared_poll() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    POLLS.store(0, Ordering::Release);
    let (iface, dev) = fixture();
    let mut napi = napi(dev);

    // SAFETY: test-owned NAPI and net_device storage remain live through the calls.
    unsafe {
        assert!(napi_schedule_prep(&mut napi));
        assert!(net::sock::stack().unregister_iface(iface));
        __napi_schedule(&mut napi);
        crate::linux_netdev::alloc::free_netdev(dev);
    }
    assert_eq!(POLLS.load(Ordering::Acquire), 0);
}

#[test]
fn losing_prepare_preserves_scheduled_generation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (iface, dev) = fixture();
    let mut napi = napi(dev);
    let scheduled_generation = u64::MAX;
    napi.state.store(NAPI_STATE_SCHEDULED, Ordering::Release);
    napi.ingress_generation.store(scheduled_generation, Ordering::Release);

    // SAFETY: test-owned NAPI and net_device storage remain live through the call.
    unsafe {
        assert!(!napi_schedule_prep(&mut napi));
        assert_eq!(napi.ingress_generation.load(Ordering::Acquire), scheduled_generation);
        cleanup(iface, dev);
    }
}

#[test]
fn disable_cancels_prepared_generation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    POLLS.store(0, Ordering::Release);
    let (iface, dev) = fixture();
    let mut napi = napi(dev);

    // SAFETY: test-owned NAPI and net_device storage remain live through the calls.
    unsafe {
        assert!(napi_schedule_prep(&mut napi));
        napi_disable(&mut napi);
        __napi_schedule(&mut napi);
        assert_eq!(napi.state.load(Ordering::Acquire), NAPI_STATE_DISABLED);
        assert_eq!(napi.ingress_generation.load(Ordering::Acquire), 0);
        cleanup(iface, dev);
    }
    assert_eq!(POLLS.load(Ordering::Acquire), 0);
}
