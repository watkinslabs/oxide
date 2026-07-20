use super::*;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::vec;

const RAW: u8 = 3;
const SOURCE: [u8; 6] = [2, 3, 4, 5, 6, 7];

struct DispatchDev {
    active: AtomicUsize,
    maximum: AtomicUsize,
    entered: AtomicBool,
    release: AtomicBool,
    calls: Mutex<Vec<u8>>,
}

impl DispatchDev {
    fn new(block: bool) -> Self {
        Self { active: AtomicUsize::new(0), maximum: AtomicUsize::new(0),
            entered: AtomicBool::new(false), release: AtomicBool::new(!block),
            calls: Mutex::new(Vec::new()) }
    }

    fn enter(&self, id: u8) -> NetResult<()> {
        let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
        self.maximum.fetch_max(active, Ordering::AcqRel);
        self.calls.lock().unwrap().push(id);
        if id == 1 {
            self.entered.store(true, Ordering::Release);
            while !self.release.load(Ordering::Acquire) { std::thread::yield_now(); }
        }
        self.active.fetch_sub(1, Ordering::AcqRel);
        Ok(())
    }
}

impl NetDev for DispatchDev {
    fn name(&self) -> &str { "dispatch0" }
    fn mac(&self) -> MacAddr { MacAddr(SOURCE) }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, pkt: Pkt) -> NetResult<()> { self.enter(pkt.data()[0]) }
    fn xmit_raw(&self, frame: &[u8]) -> NetResult<()> { self.enter(frame[14]) }
    fn xmit_raw_direct(&self, frame: &[u8]) -> NetResult<()> { self.enter(frame[14]) }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> NamespaceDropAction { NamespaceDropAction::Destroy }
}

fn frame(id: u8) -> Vec<u8> {
    let mut frame = alloc::vec![0; crate::ethernet::ETH_HDR_LEN + 1];
    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&SOURCE);
    frame[12..14].copy_from_slice(&crate::eth_p::IPV4.to_be_bytes());
    frame[14] = id;
    frame
}

fn packet(id: u8) -> Pkt {
    let mut pkt = Pkt::new(1);
    pkt.data_mut()[0] = id;
    pkt.proto = crate::eth_p::IPV4;
    pkt
}

fn unresolved_packet() -> Pkt {
    let mut pkt = Pkt::new(20);
    pkt.proto = crate::eth_p::IPV4;
    pkt.next_hop = Some(crate::pkt::TxNextHop::V4(crate::Ipv4Addr::new(192, 0, 2, 2)));
    let data = pkt.data_mut();
    data[0] = 0x45;
    data[12..16].copy_from_slice(&[192, 0, 2, 1]);
    pkt
}

fn packet_count(socket: &crate::sock::InetSocket) -> usize {
    let kind = socket.kind.lock();
    let crate::sock::SockKind::Packet { rx, .. } = &*kind else { return 0 };
    let count = rx.lock().len();
    count
}

#[test]
fn queued_tx_is_peer_visible_once_and_direct_tx_is_hidden() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let observer = Arc::new(crate::sock::InetSocket::new_packet_in(
        crate::eth_p::ALL, RAW, owner.clone()));
    crate::sock::register_packet(&observer);
    let stack = crate::NetStack::new();
    let dev = Arc::new(DispatchDev::new(false));
    let iface = stack.ifaces.register_in_ns(dev.clone(), owner.id().as_u64());
    let lease = stack.ifaces.acquire_egress_in_ns(iface, owner.id().as_u64()).unwrap();

    lease.xmit(packet(3)).unwrap();
    lease.xmit_raw_from(&frame(4), None).unwrap();
    assert_eq!(packet_count(&observer), 2);
    lease.xmit_raw_policy_from(&frame(5), None, true).unwrap();
    assert_eq!(packet_count(&observer), 2);
    assert_eq!(*dev.calls.lock().unwrap(), vec![3, 4, 5]);
}

#[test]
fn mixed_queued_and_direct_tx_has_one_hardware_owner_and_fifo_queue() {
    let stack = Arc::new(crate::NetStack::new());
    let dev = Arc::new(DispatchDev::new(true));
    let iface = stack.ifaces.register(dev.clone());
    let lease = stack.ifaces.acquire_egress_in_ns(iface, 0).unwrap();

    let first = lease.clone();
    let first_tx = std::thread::spawn(move || first.xmit(packet(1)));
    while !dev.entered.load(Ordering::Acquire) { std::thread::yield_now(); }

    let second = lease.clone();
    let second_tx = std::thread::spawn(move || second.xmit_raw_from(&frame(2), None));
    while lease.queued_tx() != 1 { std::thread::yield_now(); }
    let third = lease.clone();
    let third_tx = std::thread::spawn(move || third.xmit_raw_from(&frame(3), None));
    while lease.queued_tx() != 2 { std::thread::yield_now(); }
    let direct = lease.clone();
    let direct_tx = std::thread::spawn(move || {
        direct.xmit_raw_policy_from(&frame(9), None, true)
    });

    for _ in 0..100 { std::thread::yield_now(); }
    assert_eq!(dev.maximum.load(Ordering::Acquire), 1);
    dev.release.store(true, Ordering::Release);
    first_tx.join().unwrap().unwrap();
    second_tx.join().unwrap().unwrap();
    third_tx.join().unwrap().unwrap();
    direct_tx.join().unwrap().unwrap();

    let calls = dev.calls.lock().unwrap().clone();
    let queued = calls.into_iter().filter(|id| *id != 9).collect::<Vec<_>>();
    assert_eq!(queued, vec![1, 2, 3]);
    assert_eq!(dev.maximum.load(Ordering::Acquire), 1);
}

#[test]
fn full_dispatch_fifo_returns_enobufs() {
    let stack = Arc::new(crate::NetStack::new());
    let dev = Arc::new(DispatchDev::new(true));
    let iface = stack.ifaces.register(dev.clone());
    let lease = stack.ifaces.acquire_egress_in_ns(iface, 0).unwrap();
    let first = lease.clone();
    let first_tx = std::thread::spawn(move || first.xmit(packet(1)));
    while !dev.entered.load(Ordering::Acquire) { std::thread::yield_now(); }

    let mut pending = Vec::new();
    for at in 0..super::super::tx_dispatch::TX_QUEUE_CAPACITY {
        let queued = lease.clone();
        pending.push(std::thread::spawn(move || queued.xmit_raw_from(&frame(2), None)));
        while lease.queued_tx() != at + 1 { std::thread::yield_now(); }
    }
    assert_eq!(lease.xmit_raw_from(&frame(3), None), Err(NetError::Enobufs));

    dev.release.store(true, Ordering::Release);
    first_tx.join().unwrap().unwrap();
    for tx in pending { tx.join().unwrap().unwrap(); }
    assert_eq!(dev.calls.lock().unwrap().len(),
        super::super::tx_dispatch::TX_QUEUE_CAPACITY + 1);
}

#[test]
fn unresolved_arp_retries_then_completes_host_unreachable() {
    let stack = Arc::new(crate::NetStack::new());
    let dev = Arc::new(DispatchDev::new(false));
    let iface = stack.ifaces.register(dev.clone());
    let lease = stack.ifaces.acquire_egress_in_ns(iface, 0).unwrap();
    let transmit = std::thread::spawn(move || lease.xmit(unresolved_packet()));

    while dev.calls.lock().unwrap().len() != 1 { std::thread::yield_now(); }
    for probe in 1..crate::arp::ARP_MCAST_SOLICIT {
        stack.arp_tick(u64::from(probe) * crate::arp::ARP_RETRANS_TIME_NS);
        while dev.calls.lock().unwrap().len() != usize::from(probe) + 1 {
            std::thread::yield_now();
        }
    }
    stack.arp_tick(u64::from(crate::arp::ARP_MCAST_SOLICIT) * crate::arp::ARP_RETRANS_TIME_NS);
    assert_eq!(transmit.join().unwrap(), Err(NetError::Ehostunreach));
    assert_eq!(dev.calls.lock().unwrap().len(), usize::from(crate::arp::ARP_MCAST_SOLICIT));
}
