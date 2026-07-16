use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

struct ControlDev;

impl crate::NetDev for ControlDev {
    fn name(&self) -> &str { "ctl0" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, _pkt: crate::Pkt) -> crate::NetResult<()> { Ok(()) }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::MoveToInitial
    }
}

struct BlockingControlDev {
    entered: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
    retired: Arc<AtomicBool>,
}

struct OrderedControlDev {
    seen: Arc<std::sync::Mutex<alloc::vec::Vec<Option<Ipv4Addr>>>>,
}

impl crate::NetDev for OrderedControlDev {
    fn name(&self) -> &str { "ordered0" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, _pkt: crate::Pkt) -> crate::NetResult<()> { Ok(()) }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn ipv4_addr_changed(&self, addr: Option<Ipv4Addr>) {
        self.seen.lock().unwrap().push(addr);
    }
}

impl crate::NetDev for BlockingControlDev {
    fn name(&self) -> &str { "blocking0" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, _pkt: crate::Pkt) -> crate::NetResult<()> { Ok(()) }
    fn retire_namespace(&self) { self.retired.store(true, Ordering::Release); }
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn ipv4_addr_changed(&self, _addr: Option<Ipv4Addr>) {
        self.entered.store(true, Ordering::Release);
        while !self.release.load(Ordering::Acquire) { std::thread::yield_now(); }
        assert!(!self.retired.load(Ordering::Acquire));
    }
}

fn claim(stack: &crate::NetStack, ns: u64, iface: NetIfaceId)
    -> crate::netdev::IfaceTeardown
{
    let _rtnl = stack.rtnl_lock();
    match stack.ifaces.claim_unregister_in(iface, Some(ns)) {
        crate::netdev::IfaceUnregisterClaim::Teardown(teardown) => teardown,
        _ => panic!("expected teardown claim"),
    }
}

#[test]
fn set_addr_and_mask_share_one_row() {
    let iface = NetIfaceId::from_raw(88);
    set_primary_addr(901, iface, Ipv4Addr::new(10, 1, 2, 3), 0);
    set_primary_mask(901, iface, 0xffff_ff00);
    assert_eq!(primary(901, iface), Some((Ipv4Addr::new(10, 1, 2, 3), 0xffff_ff00)));
    assert_eq!(snapshot_ns(901).iter().filter(|r| r.iface == iface).count(), 1);
    let _ = remove(901, iface, Ipv4Addr::new(10, 1, 2, 3), 24);
}

#[test]
fn explicit_broadcast_overrides_subnet_fallback() {
    let ns = 912;
    let iface = NetIfaceId::from_raw(912);
    insert(Ipv4IfaceAddr { ns, iface, addr: Ipv4Addr::new(192, 0, 2, 9), peer: None,
        prefixlen: 24, mask: 0xffff_ff00, broadcast: Some(Ipv4Addr::new(192, 0, 2, 254)),
        scope: 0, flags: IFA_F_PERMANENT, cacheinfo: Ipv4AddrCacheInfo::PERMANENT });
    assert_eq!(broadcast(ns, iface), Some(Ipv4Addr::new(192, 0, 2, 254)));
    remove(ns, iface, Ipv4Addr::new(192, 0, 2, 9), 24);
}

#[test]
fn close_before_commit_rejects_address_and_flag_mutation() {
    const NS: u64 = 0x8440_001;
    let stack = crate::NetStack::new();
    let iface = stack.ifaces.register_in_ns(alloc::sync::Arc::new(ControlDev), NS);
    let initial = stack.ifaces.iface_flags(iface).unwrap();
    let teardown = claim(&stack, NS, iface);

    assert!(!stack.set_primary_ipv4_in(NS, iface, Ipv4Addr::new(192, 0, 2, 1), 0));
    let rtnl = stack.rtnl_lock();
    assert_eq!(stack.ifaces.set_iface_flags_in_ns(
        &rtnl, iface, NS, 0, crate::netdev::iff::IFF_UP), None);
    drop(rtnl);
    assert_eq!(primary(NS, iface), None);
    assert_eq!(stack.ifaces.iface_flags(iface), None);
    assert_eq!(teardown.net_ns(), NS);
    assert_ne!(initial, 0);
}

#[test]
fn move_generation_rejects_old_and_resume_pending_control_mutation() {
    let _domain = crate::hosted_fixture::init_net_domain();
    const NS: u64 = 0x8440_002;
    let stack = crate::NetStack::new();
    let iface = stack.ifaces.register_in_ns(alloc::sync::Arc::new(ControlDev), NS);
    let teardown = claim(&stack, NS, iface);
    teardown.wait();
    let next = {
        let _rtnl = stack.rtnl_lock();
        stack.ifaces.begin_move_to_initial(&teardown).unwrap()
    };

    assert!(!stack.set_primary_ipv4_in(NS, iface, Ipv4Addr::new(198, 51, 100, 1), 0));
    assert!(!stack.set_primary_ipv4_in(0, iface, Ipv4Addr::new(198, 51, 100, 2), 0));
    {
        let _rtnl = stack.rtnl_lock();
        assert_eq!(stack.ifaces.set_iface_flags_in_ns(
            &_rtnl, iface, NS, 0, crate::netdev::iff::IFF_UP), None);
        assert_eq!(stack.ifaces.set_iface_flags_in_ns(
            &_rtnl, iface, 0, 0, crate::netdev::iff::IFF_UP), None);
        assert!(stack.ifaces.finish_move_to_initial(&teardown, &next));
    }

    assert!(!stack.set_primary_ipv4_in(NS, iface, Ipv4Addr::new(198, 51, 100, 3), 0));
    assert!(stack.set_primary_ipv4_in(0, iface, Ipv4Addr::new(198, 51, 100, 4), 0));
    {
        let rtnl = stack.rtnl_lock();
        assert_eq!(stack.ifaces.set_iface_flags_in_ns(
            &rtnl, iface, NS, 0, crate::netdev::iff::IFF_UP), None);
        assert!(stack.ifaces.set_iface_flags_in_ns(
            &rtnl, iface, 0, 0, crate::netdev::iff::IFF_UP).is_some());
    }
    assert_eq!(primary(NS, iface), None);
    assert_eq!(primary(0, iface).map(|row| row.0), Some(Ipv4Addr::new(198, 51, 100, 4)));
    let _ = remove_iface(0, iface);
}

#[test]
fn teardown_drains_generation_qualified_address_side_effect() {
    const NS: u64 = 0x8440_003;
    let stack = Arc::new(crate::NetStack::new());
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let retired = Arc::new(AtomicBool::new(false));
    let iface = stack.ifaces.register_in_ns(Arc::new(BlockingControlDev {
        entered: entered.clone(), release: release.clone(), retired: retired.clone(),
    }), NS);
    let setter_stack = stack.clone();
    let setter = std::thread::spawn(move || {
        setter_stack.set_primary_ipv4_in(NS, iface, Ipv4Addr::new(203, 0, 113, 1), 0)
    });
    while !entered.load(Ordering::Acquire) { std::thread::yield_now(); }

    let teardown_stack = stack.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let teardown = std::thread::spawn(move || {
        done_tx.send(teardown_stack.teardown_iface_in(NS, iface)).unwrap();
    });
    for _ in 0..1000 { std::thread::yield_now(); }
    assert!(matches!(done_rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));
    assert!(!retired.load(Ordering::Acquire));

    release.store(true, Ordering::Release);
    assert!(setter.join().unwrap());
    assert!(done_rx.recv().unwrap());
    teardown.join().unwrap();
    assert!(retired.load(Ordering::Acquire));
}

#[test]
fn address_effects_publish_primary_promotion_and_clear_in_commit_order() {
    const NS: u64 = 0x8440_004;
    let stack = Arc::new(crate::NetStack::new());
    let seen = Arc::new(std::sync::Mutex::new(alloc::vec::Vec::new()));
    let iface = stack.ifaces.register_in_ns(Arc::new(OrderedControlDev { seen: seen.clone() }), NS);
    let (first, second, promote, clear) = {
        let rtnl = stack.rtnl_lock();
        let generation = stack.ifaces.control_generation_in_ns(&rtnl, iface, NS).unwrap();
        let first = stack.set_primary_ipv4_generation_rtnl(&rtnl, NS, iface, generation,
            Ipv4Addr::new(192, 0, 2, 1), 0).unwrap();
        let second = stack.set_ipv4_prefix_meta_generation_rtnl(&rtnl, NS, iface, generation,
            Ipv4Addr::new(192, 0, 2, 2), None, 24, 0, IFA_F_PERMANENT,
            Ipv4AddrCacheInfo::PERMANENT).unwrap();
        let (_, promote) = stack.remove_ipv4_prefix_generation_rtnl(&rtnl, NS, iface,
            generation, Ipv4Addr::new(192, 0, 2, 1), None, 0).unwrap();
        let (_, clear) = stack.remove_ipv4_prefix_generation_rtnl(&rtnl, NS, iface,
            generation, Ipv4Addr::new(192, 0, 2, 2), None, 24).unwrap();
        (first, second, promote, clear)
    };
    let later = std::thread::spawn(move || clear.publish());
    for _ in 0..1000 { std::thread::yield_now(); }
    assert!(seen.lock().unwrap().is_empty());
    first.publish();
    second.publish();
    promote.publish();
    later.join().unwrap();
    assert_eq!(*seen.lock().unwrap(), alloc::vec![
        Some(Ipv4Addr::new(192, 0, 2, 1)), Some(Ipv4Addr::new(192, 0, 2, 1)),
        Some(Ipv4Addr::new(192, 0, 2, 2)), None,
    ]);
}

#[test]
fn peer_is_canonical_row_metadata_and_exact_delete_selector() {
    const NS: u64 = 0x8440_005;
    let stack = crate::NetStack::new();
    let iface = stack.ifaces.register_in_ns(Arc::new(ControlDev), NS);
    let local = Ipv4Addr::new(192, 0, 2, 10);
    let peer = Ipv4Addr::new(192, 0, 2, 11);
    let effect = {
        let rtnl = stack.rtnl_lock();
        let generation = stack.ifaces.control_generation_in_ns(&rtnl, iface, NS).unwrap();
        stack.set_ipv4_prefix_meta_generation_rtnl(&rtnl, NS, iface, generation,
            local, Some(peer), 32, 0, IFA_F_PERMANENT,
            Ipv4AddrCacheInfo::PERMANENT).unwrap()
    };
    effect.publish();
    let wrong = {
        let rtnl = stack.rtnl_lock();
        let generation = stack.ifaces.control_generation_in_ns(&rtnl, iface, NS).unwrap();
        stack.remove_ipv4_prefix_generation_rtnl(&rtnl, NS, iface, generation,
            local, Some(Ipv4Addr::new(192, 0, 2, 12)), 32).is_none()
    };
    assert!(wrong);
    let removed = {
        let rtnl = stack.rtnl_lock();
        let generation = stack.ifaces.control_generation_in_ns(&rtnl, iface, NS).unwrap();
        stack.remove_ipv4_prefix_generation_rtnl(&rtnl, NS, iface, generation,
            local, Some(peer), 32).unwrap()
    };
    assert_eq!(removed.0.peer, Some(peer));
    assert_eq!(removed.0.address(), peer);
    removed.1.publish();
    let _ = stack.ifaces.unregister(iface);
}
