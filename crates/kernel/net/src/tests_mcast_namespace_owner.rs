use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

struct FailingMcastDev {
    attempts: AtomicUsize,
    fail: AtomicBool,
    net_ns: u64,
    owner: Mutex<Option<network_namespace::NetworkNamespaceRef>>,
    saw_live_owner: AtomicBool,
}

impl FailingMcastDev {
    fn new(net_ns: u64, owner: Option<network_namespace::NetworkNamespaceRef>) -> Self {
        Self { attempts: AtomicUsize::new(0), fail: AtomicBool::new(true), net_ns,
            owner: Mutex::new(owner), saw_live_owner: AtomicBool::new(false) }
    }
}

impl crate::NetDev for FailingMcastDev {
    fn name(&self) -> &str { "mcast-owner" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, _pkt: crate::Pkt) -> crate::NetResult<()> {
        self.attempts.fetch_add(1, Ordering::AcqRel);
        if self.fail.load(Ordering::Acquire) { return Err(crate::NetError::Eio); }
        drop(self.owner.lock().unwrap().take());
        self.saw_live_owner.store(network_namespace::lookup_u64(self.net_ns).is_some(), Ordering::Release);
        Ok(())
    }
}

fn namespace() -> network_namespace::NetworkNamespaceRef {
    crate::net_ns::test_support::allocate_namespace()
}

#[test]
fn igmp_retry_skips_dead_namespace_owner() {
    let owner = namespace();
    let net_ns = owner.id().as_u64();
    let stack = NetStack::new();
    let dev = Arc::new(FailingMcastDev::new(net_ns, None));
    let iface = stack.ifaces.register_in_ns(dev.clone() as Arc<dyn crate::NetDev>, net_ns);
    let group = Ipv4Addr::new(239, 7, 8, 9);
    stack.join_ipv4_multicast_in(net_ns, iface, group, Ipv4Addr::LOOPBACK).unwrap();
    assert_eq!(dev.attempts.load(Ordering::Acquire), 1);

    drop(owner);
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
    assert_eq!(dev.attempts.load(Ordering::Acquire), 1);
    assert!(stack.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|entry| {
        entry.group == group && entry.change.as_ref().is_some_and(|change| change.remaining == 1)
    })));
}

#[test]
fn igmp_retry_holds_namespace_owner_through_report_drive() {
    let owner = namespace();
    let net_ns = owner.id().as_u64();
    let stack = NetStack::new();
    let dev = Arc::new(FailingMcastDev::new(net_ns, Some(owner)));
    let iface = stack.ifaces.register_in_ns(dev.clone() as Arc<dyn crate::NetDev>, net_ns);
    let group = Ipv4Addr::new(239, 7, 8, 10);
    stack.join_ipv4_multicast_in(net_ns, iface, group, Ipv4Addr::LOOPBACK).unwrap();

    dev.fail.store(false, Ordering::Release);
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
    assert!(dev.saw_live_owner.load(Ordering::Acquire));
    assert!(network_namespace::lookup_u64(net_ns).is_none());
}

#[test]
fn mld_retry_skips_dead_namespace_owner() {
    let owner = namespace();
    let net_ns = owner.id().as_u64();
    let stack = NetStack::new();
    let dev = Arc::new(FailingMcastDev::new(net_ns, None));
    let iface = stack.ifaces.register_in_ns(dev.clone() as Arc<dyn crate::NetDev>, net_ns);
    let source = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x3349]);
    stack.join_ipv6_multicast_in(net_ns, iface, group, source).unwrap();
    assert_eq!(dev.attempts.load(Ordering::Acquire), 1);

    drop(owner);
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
    assert_eq!(dev.attempts.load(Ordering::Acquire), 1);
    assert!(stack.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|entry| {
        entry.group == group && entry.change.as_ref().is_some_and(|change| change.remaining == 1)
    })));
}

#[test]
fn mld_retry_holds_namespace_owner_through_report_drive() {
    let owner = namespace();
    let net_ns = owner.id().as_u64();
    let stack = NetStack::new();
    let dev = Arc::new(FailingMcastDev::new(net_ns, Some(owner)));
    let iface = stack.ifaces.register_in_ns(dev.clone() as Arc<dyn crate::NetDev>, net_ns);
    let source = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x3350]);
    stack.join_ipv6_multicast_in(net_ns, iface, group, source).unwrap();

    dev.fail.store(false, Ordering::Release);
    stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
    assert!(dev.saw_live_owner.load(Ordering::Acquire));
    assert!(network_namespace::lookup_u64(net_ns).is_none());
}
