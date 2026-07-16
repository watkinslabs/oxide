use super::*;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc as StdArc, Barrier};

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn fixture_guard() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct ModeDev {
    mode: Spinlock<crate::PacketRxMode, SockLockClass>,
    move_to_initial: bool,
}

impl ModeDev {
    fn new(move_to_initial: bool) -> Self {
        Self { mode: Spinlock::new(crate::PacketRxMode::default()), move_to_initial }
    }
}

impl crate::NetDev for ModeDev {
    fn name(&self) -> &str { "packet-membership" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr([2, 0, 0, 0, 0, 1]) }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, _pkt: crate::Pkt) -> crate::NetResult<()> { Ok(()) }
    fn packet_rx_mode_changed(&self, mode: &crate::PacketRxMode) { *self.mode.lock() = mode.clone(); }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        if self.move_to_initial { crate::NamespaceDropAction::MoveToInitial }
        else { crate::NamespaceDropAction::Destroy }
    }
}

fn request(iface: NetIfaceId, kind: u16, address: [u8; 6]) -> PacketMembershipRequest {
    let mut bytes = [0u8; 32]; bytes[..6].copy_from_slice(&address);
    PacketMembershipRequest {
        ifindex: iface.raw(), kind,
        address: crate::PacketLinkAddress { len: 6, bytes },
    }
}

fn socket(owner: network_namespace::NetworkNamespaceRef) -> Arc<InetSocket> {
    let socket = Arc::new(InetSocket::new_packet_in(crate::eth_p::ALL, 3, owner));
    register_packet(&socket);
    socket
}

#[test]
fn duplicate_and_cross_socket_refs_drive_flags_once() {
    let _fixture = fixture_guard();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let stack = stack();
    let dev = Arc::new(ModeDev::new(false));
    let iface = stack.ifaces.register_in_ns(dev.clone(), owner.id().as_u64());
    let first = socket(owner.clone());
    let second = socket(owner.clone());
    let promisc = request(iface, crate::uapi::PACKET_MR_PROMISC, [0; 6]);

    first.change_packet_membership(promisc, true).unwrap();
    first.change_packet_membership(promisc, true).unwrap();
    second.change_packet_membership(promisc, true).unwrap();
    assert!(stack.ifaces.iface_flags(iface).unwrap() & crate::netdev::iff::IFF_PROMISC != 0);
    first.change_packet_membership(promisc, false).unwrap();
    first.change_packet_membership(promisc, false).unwrap();
    assert!(dev.mode.lock().promiscuous, "second socket retains device reference");
    second.change_packet_membership(promisc, false).unwrap();
    assert!(!dev.mode.lock().promiscuous);
    assert_eq!(stack.ifaces.iface_flags(iface).unwrap() & crate::netdev::iff::IFF_PROMISC, 0);

    first.change_packet_membership(promisc, true).unwrap();
    {
        let rtnl = stack.rtnl_lock();
        stack.ifaces.set_iface_flags_in_ns(&rtnl, iface, owner.id().as_u64(), 0,
            crate::netdev::iff::IFF_UP).unwrap();
    }
    first.change_packet_membership(promisc, false).unwrap();
    assert!(!dev.mode.lock().promiscuous,
        "unrelated flag update must not retain effective packet mode as admin intent");

    {
        let rtnl = stack.rtnl_lock();
        stack.ifaces.set_iface_flags_in_ns(&rtnl, iface, owner.id().as_u64(),
            crate::netdev::iff::IFF_PROMISC, crate::netdev::iff::IFF_PROMISC).unwrap();
    }
    first.change_packet_membership(promisc, true).unwrap();
    first.change_packet_membership(promisc, false).unwrap();
    assert!(dev.mode.lock().promiscuous, "administrative mode survives packet drop");
    {
        let rtnl = stack.rtnl_lock();
        stack.ifaces.set_iface_flags_in_ns(&rtnl, iface, owner.id().as_u64(), 0,
            crate::netdev::iff::IFF_PROMISC).unwrap();
    }
    assert!(!dev.mode.lock().promiscuous);
    assert!(stack.unregister_iface_in(owner.id().as_u64(), iface));
}

#[test]
fn address_memberships_validate_and_snapshot_exact_filters() {
    let _fixture = fixture_guard();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let stack = stack();
    let iface = stack.ifaces.register_in_ns(Arc::new(ModeDev::new(false)), owner.id().as_u64());
    let socket = socket(owner.clone());
    let multicast = request(iface, crate::uapi::PACKET_MR_MULTICAST, [1, 0, 94, 0, 0, 1]);
    let unicast = request(iface, crate::uapi::PACKET_MR_UNICAST, [2, 0, 0, 0, 0, 9]);
    let mut short = multicast; short.address.len = 5;

    assert_eq!(socket.change_packet_membership(short, true), Err(crate::NetError::Einval));
    socket.change_packet_membership(multicast, true).unwrap();
    socket.change_packet_membership(unicast, true).unwrap();
    let mode = stack.ifaces.packet_rx_mode(iface, owner.id().as_u64()).unwrap();
    assert_eq!(mode.multicast, alloc::vec![multicast.address]);
    assert_eq!(mode.unicast, alloc::vec![unicast.address]);
    socket.change_packet_membership(multicast, false).unwrap();
    socket.change_packet_membership(unicast, false).unwrap();
    assert_eq!(stack.ifaces.packet_rx_mode(iface, owner.id().as_u64()).unwrap(),
        crate::PacketRxMode::default());
    assert!(stack.unregister_iface_in(owner.id().as_u64(), iface));
}

#[test]
fn final_close_flushes_every_unique_device_reference() {
    let _fixture = fixture_guard();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let stack = stack();
    let dev = Arc::new(ModeDev::new(false));
    let iface = stack.ifaces.register_in_ns(dev.clone(), owner.id().as_u64());
    let socket = socket(owner.clone());
    socket.change_packet_membership(
        request(iface, crate::uapi::PACKET_MR_PROMISC, [0; 6]), true).unwrap();
    socket.change_packet_membership(
        request(iface, crate::uapi::PACKET_MR_ALLMULTI, [0; 6]), true).unwrap();

    socket.release_file();

    assert_eq!(socket.packet_memberships.count(), 0);
    assert_eq!(*dev.mode.lock(), crate::PacketRxMode::default());
    assert_eq!(socket.change_packet_membership(
        request(iface, crate::uapi::PACKET_MR_PROMISC, [0; 6]), true),
        Err(crate::NetError::Einval));
    assert!(stack.unregister_iface_in(owner.id().as_u64(), iface));
}

#[test]
fn close_racing_admitted_add_is_linearized_then_flushed() {
    let _fixture = fixture_guard();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let stack = stack();
    let dev = Arc::new(ModeDev::new(false));
    let iface = stack.ifaces.register_in_ns(dev.clone(), owner.id().as_u64());
    let socket = socket(owner.clone());
    let request = request(iface, crate::uapi::PACKET_MR_PROMISC, [0; 6]);
    let entered = StdArc::new(Barrier::new(2));
    let resume = StdArc::new(Barrier::new(2));
    let worker = {
        let socket = socket.clone(); let entered = entered.clone(); let resume = resume.clone();
        std::thread::spawn(move || socket.change_packet_membership_staged(request, true, || {
            entered.wait(); resume.wait();
        }))
    };
    entered.wait();
    let closing = socket.clone();
    let closed = StdArc::new(AtomicBool::new(false));
    let close_done = closed.clone();
    let closer = std::thread::spawn(move || { closing.release_file(); close_done.store(true, Ordering::Release); });
    while !socket.released.load(Ordering::Acquire) { std::thread::yield_now(); }
    assert!(!closed.load(Ordering::Acquire), "close waits behind admitted RTNL operation");
    resume.wait();
    assert_eq!(worker.join().unwrap(), Ok(()));
    closer.join().unwrap();
    assert_eq!(*dev.mode.lock(), crate::PacketRxMode::default());
    assert_eq!(socket.packet_memberships.count(), 0);
    assert!(stack.unregister_iface_in(owner.id().as_u64(), iface));
}

#[test]
fn unregister_detaches_memberships_bind_and_rejects_late_add() {
    let _fixture = fixture_guard();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let net_ns = owner.id().as_u64();
    let stack = stack();
    let dev = Arc::new(ModeDev::new(false));
    let iface = stack.ifaces.register_in_ns(dev.clone(), net_ns);
    let socket = socket(owner.clone());
    if let SockKind::Packet { ifindex, .. } = &*socket.kind.lock() {
        ifindex.store(iface.raw(), Ordering::Release);
    }
    let membership = request(iface, crate::uapi::PACKET_MR_PROMISC, [0; 6]);
    socket.change_packet_membership(membership, true).unwrap();
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();
    let removing = std::thread::spawn(move || stack.unregister_iface_in(net_ns, iface));
    while stack.ifaces.acquire_ingress(iface).is_some() {
        std::thread::yield_now();
    }
    assert_eq!(socket.change_packet_membership(membership, true), Err(crate::NetError::Enodev));
    drop(lease);
    assert!(removing.join().unwrap());
    assert_eq!(socket.packet_memberships.count(), 0);
    let kind = socket.kind.lock();
    let SockKind::Packet { ifindex, .. } = &*kind else { panic!("packet socket") };
    assert_eq!(ifindex.load(Ordering::Acquire), u32::MAX);
    assert_eq!(socket.error.take(), syscall::errno::Errno::Enetdown as i32);
    assert_eq!(*dev.mode.lock(), crate::PacketRxMode::default());
}

#[test]
fn namespace_move_drops_old_memberships_before_initial_publication() {
    let _fixture = fixture_guard();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let net_ns = owner.id().as_u64();
    let stack = stack();
    let dev = Arc::new(ModeDev::new(true));
    let iface = stack.ifaces.register_in_ns(dev.clone(), net_ns);
    let socket = socket(owner.clone());
    socket.change_packet_membership(
        request(iface, crate::uapi::PACKET_MR_ALLMULTI, [0; 6]), true).unwrap();

    assert!(stack.teardown_iface_in(net_ns, iface));

    assert_eq!(stack.ifaces.namespace(iface), Some(0));
    assert_eq!(socket.packet_memberships.count(), 0);
    assert_eq!(*dev.mode.lock(), crate::PacketRxMode::default());
    assert_eq!(stack.ifaces.iface_flags(iface).unwrap() &
        (crate::netdev::iff::IFF_PROMISC | crate::netdev::iff::IFF_ALLMULTI), 0);
    assert!(stack.unregister_iface(iface));
}
