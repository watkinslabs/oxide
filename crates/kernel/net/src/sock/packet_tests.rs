use super::*;
use crate::bpf_filter::{FilterContext, FilterKind, FilterProgram, install_bpf_filter_context_runner};
use crate::{PacketChecksum, PacketRxMetadata};
use core::sync::atomic::{AtomicUsize, Ordering};

const RAW: u8 = 3;
const DGRAM: u8 = 2;
const SOURCE: [u8; 6] = [2, 3, 4, 5, 6, 7];
const LOCAL: [u8; 6] = [2, 9, 8, 7, 6, 5];

struct FramingDev { sent: AtomicUsize }

impl FramingDev {
    fn new() -> Self { Self { sent: AtomicUsize::new(0) } }
}

impl crate::NetDev for FramingDev {
    fn name(&self) -> &str { "packet0" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr(LOCAL) }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, _pkt: crate::Pkt) -> crate::NetResult<()> {
        self.sent.fetch_add(1, Ordering::Relaxed); Ok(())
    }
    fn xmit_observed(&self, pkt: crate::Pkt,
                     observe: &mut dyn FnMut(&[u8], u16, usize)) -> crate::NetResult<()> {
        let mut frame = alloc::vec![0; 14 + pkt.len()];
        crate::ethernet::EthHdr::write_to(crate::MacAddr::BROADCAST,
            crate::MacAddr(LOCAL), pkt.proto, &mut frame[..14]);
        frame[14..].copy_from_slice(pkt.data());
        observe(&frame, pkt.proto, 14);
        self.sent.fetch_add(1, Ordering::Relaxed); Ok(())
    }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
}

fn packet(owner: network_namespace::NetworkNamespaceRef, kind: u8) -> Arc<InetSocket> {
    packet_protocol(owner, kind, crate::eth_p::ALL)
}

fn packet_protocol(owner: network_namespace::NetworkNamespaceRef, kind: u8,
                   protocol: u16) -> Arc<InetSocket> {
    let socket = Arc::new(InetSocket::new_packet_in(protocol, kind, owner));
    register_packet(&socket);
    socket
}

fn take(socket: &InetSocket) -> Vec<PacketFrame> {
    let kind = socket.kind.lock();
    let SockKind::Packet { rx, .. } = &*kind else { panic!("packet socket") };
    let limit = socket.opts.rcvbuf.load(Ordering::Acquire).max(0) as usize;
    let frames = rx.lock().take_all(limit);
    frames
}

fn count(socket: &InetSocket) -> usize {
    let kind = socket.kind.lock();
    let SockKind::Packet { rx, .. } = &*kind else { return 0 };
    let count = rx.lock().len();
    count
}

fn accounting(socket: &InetSocket) -> (usize, bool) {
    let kind = socket.kind.lock();
    let SockKind::Packet { rx, .. } = &*kind else { return (0, false) };
    let accounting = rx.lock().accounting();
    accounting
}

#[test]
fn ignore_outgoing_does_not_suppress_loopback_receive_view() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let sender = packet(owner.clone(), RAW);
    let observer = packet(owner.clone(), RAW);
    let non_packet = InetSocket::new_udp_in(owner.clone());
    assert_eq!(non_packet.set_packet_ignore_outgoing(true),
        Err(crate::NetError::Enoprotoopt));
    assert_eq!(non_packet.packet_ignore_outgoing(), Err(crate::NetError::Enoprotoopt));
    assert_eq!(observer.packet_ignore_outgoing(), Ok(false));
    observer.set_packet_ignore_outgoing(true).unwrap();
    assert_eq!(observer.packet_ignore_outgoing(), Ok(true));

    let stack = crate::NetStack::new();
    let loopback = Arc::new(crate::LoopbackDev::new());
    let iface = stack.ifaces.register_in_ns(loopback.clone(), owner.id().as_u64());
    let egress = stack.ifaces.acquire_egress_in_ns(iface, owner.id().as_u64()).unwrap();
    let wire = frame(crate::MacAddr::BROADCAST.0);
    egress.xmit_raw_from(&wire, Some(packet_origin(&sender))).unwrap();
    assert_eq!(count(&observer), 1, "loopback receive is injected synchronously");

    let lease = stack.ifaces.acquire_ingress(iface).unwrap();
    stack.drain_loopback_in(&lease, &loopback);
    let rows = take(&observer);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].addr.pkttype, crate::uapi::PACKET_MULTICAST,
        "loopback ingress remains independently observable");

    observer.set_packet_ignore_outgoing(false).unwrap();
    egress.xmit_raw_from(&wire, Some(packet_origin(&sender))).unwrap();
    assert_eq!(count(&observer), 2, "ETH_P_ALL sees outgoing and receive packet taps");
    stack.drain_loopback_in(&lease, &loopback);
    let rows = take(&observer);
    assert_eq!(rows.iter().map(|row| row.addr.pkttype).collect::<Vec<_>>(),
        [crate::uapi::PACKET_OUTGOING, crate::uapi::PACKET_MULTICAST]);
}

fn frame(destination: [u8; 6]) -> Vec<u8> {
    let mut frame = alloc::vec![0; 14 + 24];
    frame[..6].copy_from_slice(&destination);
    frame[6..12].copy_from_slice(&SOURCE);
    frame[12..14].copy_from_slice(&crate::eth_p::IPV4.to_be_bytes());
    frame[14] = 0x45;
    frame
}

fn encoded_verdict(_kind: FilterKind, insns: &[u8], _context: FilterContext<'_>) -> u32 {
    u32::from_ne_bytes(insns.try_into().unwrap())
}

#[test]
fn ethernet_ingress_preserves_views_types_filters_and_namespace() {
    install_bpf_filter_context_runner(encoded_verdict);
    let owner = crate::net_ns::test_support::allocate_namespace();
    let foreign_owner = crate::net_ns::test_support::allocate_namespace();
    let raw = packet(owner.clone(), RAW);
    let datagram = packet(owner.clone(), DGRAM);
    datagram.bpf_filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: 4u32.to_ne_bytes().to_vec(),
    }).unwrap();
    let dropped = packet(owner.clone(), RAW);
    dropped.bpf_filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: 0u32.to_ne_bytes().to_vec(),
    }).unwrap();
    let foreign = packet(foreign_owner, RAW);
    let stack = crate::NetStack::new();
    let iface = stack.ifaces.register_in_ns(Arc::new(FramingDev::new()), owner.id().as_u64());
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();

    for destination in [crate::MacAddr::BROADCAST.0, [1, 0, 94, 0, 0, 1], LOCAL,
        [2, 0, 0, 0, 0, 99]]
    {
        deliver_packet_ingress_in(&lease, &frame(destination));
    }

    let raw_frames = take(&raw);
    assert_eq!(raw_frames.len(), 4, "one observation per ingress frame");
    assert_eq!(raw_frames.iter().map(|row| row.addr.pkttype).collect::<Vec<_>>(),
        [crate::uapi::PACKET_BROADCAST, crate::uapi::PACKET_MULTICAST,
         crate::uapi::PACKET_HOST, crate::uapi::PACKET_OTHERHOST]);
    assert_eq!(raw_frames[0].payload, frame(crate::MacAddr::BROADCAST.0));
    assert_eq!(raw_frames[0].addr.addr[..6], SOURCE);
    assert_eq!(raw_frames[0].addr.protocol, crate::eth_p::IPV4);
    let datagrams = take(&datagram);
    assert_eq!(datagrams.len(), 4);
    assert!(datagrams.iter().all(|row| row.payload == [0x45, 0, 0, 0]));
    assert_eq!(count(&dropped), 0);
    assert_eq!(count(&foreign), 0);
}

#[test]
fn egress_is_single_sender_suppressed_and_driver_framed() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let source = packet(owner.clone(), RAW);
    let observer = packet(owner.clone(), RAW);
    let stack = crate::NetStack::new();
    let device = Arc::new(FramingDev::new());
    let iface = stack.ifaces.register_in_ns(device.clone(), owner.id().as_u64());
    let egress = stack.ifaces.acquire_egress_in_ns(iface, owner.id().as_u64()).unwrap();
    let wire = frame(crate::MacAddr::BROADCAST.0);

    egress.xmit_raw_from(&wire, Some(packet_origin(&source))).unwrap();
    assert_eq!(count(&source), 0);
    let first = take(&observer);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].addr.pkttype, crate::uapi::PACKET_OUTGOING);
    assert_eq!(first[0].payload, wire);

    let mut local = crate::Pkt::with_capacity(0, 20);
    local.put(20).unwrap()[0] = 0x45;
    local.proto = crate::eth_p::IPV4;
    egress.xmit(local).unwrap();
    for socket in [&source, &observer] {
        let rows = take(socket);
        assert_eq!(rows.len(), 1, "driver callback publishes exactly once");
        assert_eq!(rows[0].payload.len(), 34);
        assert_eq!(&rows[0].payload[6..12], &LOCAL);
        assert_eq!(rows[0].addr.pkttype, crate::uapi::PACKET_OUTGOING);
    }
    assert_eq!(device.sent.load(Ordering::Relaxed), 2);
}

#[test]
fn loopback_network_packet_exposes_outgoing_and_headerless_host_views() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let socket = packet(owner.clone(), RAW);
    let stack = crate::NetStack::new();
    let loopback = Arc::new(crate::LoopbackDev::new());
    let iface = stack.ifaces.register_in_ns(loopback.clone(), owner.id().as_u64());
    let egress = stack.ifaces.acquire_egress_in_ns(iface, owner.id().as_u64()).unwrap();
    let mut payload = crate::Pkt::with_capacity(0, 20);
    payload.put(20).unwrap()[0] = 0x45;
    payload.proto = crate::eth_p::IPV4;

    egress.xmit(payload).unwrap();
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();
    stack.drain_loopback_in(&lease, &loopback);

    let rows = take(&socket);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows.iter().map(|row| row.addr.pkttype).collect::<Vec<_>>(),
        [crate::uapi::PACKET_OUTGOING, crate::uapi::PACKET_HOST]);
    assert!(rows.iter().all(|row| row.payload.len() == 20 && row.payload[0] == 0x45));
    assert!(rows.iter().all(|row| row.addr.hatype == 772));
}

#[test]
fn vlan_datagram_strips_all_tags_and_reports_inner_protocol() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let raw = packet(owner.clone(), RAW);
    let datagram = packet(owner.clone(), DGRAM);
    let ipv4_raw = packet_protocol(owner.clone(), RAW, crate::eth_p::IPV4);
    let ipv4_datagram = packet_protocol(owner.clone(), DGRAM, crate::eth_p::IPV4);
    let stack = crate::NetStack::new();
    let iface = stack.ifaces.register_in_ns(Arc::new(FramingDev::new()), owner.id().as_u64());
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();
    let mut tagged = frame(LOCAL);
    tagged.splice(12..14, [
        crate::eth_p::VLAN_AD.to_be_bytes()[0], crate::eth_p::VLAN_AD.to_be_bytes()[1],
        0, 1, crate::eth_p::VLAN.to_be_bytes()[0], crate::eth_p::VLAN.to_be_bytes()[1],
        0, 2, crate::eth_p::IPV4.to_be_bytes()[0], crate::eth_p::IPV4.to_be_bytes()[1],
    ]);

    deliver_packet_ingress_in(&lease, &tagged);

    let raw = take(&raw);
    assert_eq!(raw.len(), 1);
    assert_eq!(raw[0].payload, tagged);
    assert_eq!(raw[0].addr.protocol, crate::eth_p::VLAN_AD);
    let datagram = take(&datagram);
    assert_eq!(datagram.len(), 1);
    assert_eq!(datagram[0].payload, tagged[22..]);
    assert_eq!(datagram[0].addr.protocol, crate::eth_p::IPV4);
    assert_eq!(count(&ipv4_raw), 0, "RAW protocol binding sees outer QinQ type");
    let ipv4_datagram = take(&ipv4_datagram);
    assert_eq!(ipv4_datagram.len(), 1);
    assert_eq!(ipv4_datagram[0].payload, tagged[22..]);
}

#[test]
fn auxdata_preserves_capture_lengths_offsets_checksum_gso_and_vlan() {
    install_bpf_filter_context_runner(encoded_verdict);
    let owner = crate::net_ns::test_support::allocate_namespace();
    let raw = packet(owner.clone(), RAW);
    let datagram = packet(owner.clone(), DGRAM);
    datagram.bpf_filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: 4u32.to_ne_bytes().to_vec(),
    }).unwrap();
    let stack = crate::NetStack::new();
    let iface = stack.ifaces.register_in_ns(Arc::new(FramingDev::new()), owner.id().as_u64());
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();
    let mut tagged = frame(LOCAL);
    tagged.splice(12..14, [
        crate::eth_p::VLAN.to_be_bytes()[0], crate::eth_p::VLAN.to_be_bytes()[1],
        0x12, 0x34, crate::eth_p::IPV4.to_be_bytes()[0], crate::eth_p::IPV4.to_be_bytes()[1],
    ]);
    deliver_packet_ingress_meta_in(&lease, &tagged, PacketRxMetadata {
        checksum: PacketChecksum::Partial,
        virtio: crate::PacketVirtioMetadata { gso_type: 1, ..Default::default() },
        vlan: None, queue: 0,
        ..PacketRxMetadata::default()
    });

    let raw = take(&raw).remove(0);
    assert_eq!(raw.aux.len, tagged.len() as u32);
    assert_eq!(raw.aux.snaplen, tagged.len() as u32);
    assert_eq!(raw.aux.net, 18);
    assert_eq!(raw.aux.status, crate::uapi::TP_STATUS_USER
        | crate::uapi::TP_STATUS_CSUMNOTREADY | crate::uapi::TP_STATUS_GSO_TCP);
    assert_eq!((raw.aux.vlan_tci, raw.aux.vlan_tpid), (0, 0),
        "inline RAW VLAN remains in payload rather than aux offload metadata");

    let datagram = take(&datagram).remove(0);
    assert_eq!(datagram.payload, tagged[18..22]);
    assert_eq!(datagram.aux.len, (tagged.len() - 18) as u32);
    assert_eq!(datagram.aux.snaplen, 4);
    assert_eq!(datagram.aux.net, 0);
    assert_eq!(datagram.aux.vlan_tci, 0x1234);
    assert_eq!(datagram.aux.vlan_tpid, crate::eth_p::VLAN);
    assert_ne!(datagram.aux.status & crate::uapi::TP_STATUS_VLAN_VALID, 0);
    assert_ne!(datagram.aux.status & crate::uapi::TP_STATUS_VLAN_TPID_VALID, 0);
}

#[test]
fn original_device_selection_is_enqueue_time_and_namespace_exact() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let foreign_owner = crate::net_ns::test_support::allocate_namespace();
    let normal = packet(owner.clone(), RAW);
    let original = packet(owner.clone(), RAW);
    original.set_packet_origdev(true).unwrap();
    assert_eq!(original.packet_origdev(), Ok(true));
    assert_eq!(normal.packet_origdev(), Ok(false));
    assert_eq!(normal.packet_auxdata(), Ok(false));
    normal.set_packet_auxdata(true).unwrap();
    assert_eq!(normal.packet_auxdata(), Ok(true));
    let stack = crate::NetStack::new();
    let observed_iface = stack.ifaces.register_in_ns(
        Arc::new(FramingDev::new()), owner.id().as_u64());
    let original_iface = stack.ifaces.register_in_ns(
        Arc::new(FramingDev::new()), owner.id().as_u64());
    let foreign_iface = stack.ifaces.register_in_ns(
        Arc::new(FramingDev::new()), foreign_owner.id().as_u64());
    let observed_lease = stack.ifaces.acquire_ingress(observed_iface).unwrap();
    let original_lease = stack.ifaces.acquire_ingress(original_iface).unwrap();
    let foreign_lease = stack.ifaces.acquire_ingress(foreign_iface).unwrap();

    deliver_packet_ingress_from_in(&observed_lease, &original_lease, &frame(LOCAL),
        PacketRxMetadata::default());
    assert_eq!(take(&normal)[0].addr.ifindex, observed_iface.raw());
    assert_eq!(take(&original)[0].addr.ifindex, original_iface.raw());

    original.set_packet_origdev(false).unwrap();
    deliver_packet_ingress_from_in(&observed_lease, &original_lease, &frame(LOCAL),
        PacketRxMetadata::default());
    assert_eq!(take(&original)[0].addr.ifindex, observed_iface.raw(),
        "option changes affect later enqueues only");

    deliver_packet_ingress_from_in(&observed_lease, &foreign_lease, &frame(LOCAL),
        PacketRxMetadata::default());
    assert_eq!(count(&normal), 1, "foreign original identity publishes no new frame");
    assert_eq!(count(&original), 0);
}

#[test]
fn packet_skb_truesize_matches_linux_linear_and_paged_allocation_classes() {
    assert_eq!(linux_packet_skb_truesize(64), 960);
    assert_eq!(linux_packet_skb_truesize(384), 1280);
    assert_eq!(linux_packet_skb_truesize(704), 2304);
    assert_eq!(linux_packet_skb_truesize(1728), 4352);
    assert_eq!(linux_packet_skb_truesize(4096), 5056);
}

#[test]
fn packet_queue_pressure_and_statistics_are_byte_accounted_and_destructive() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let socket = packet(owner.clone(), RAW);
    let bytes = frame(LOCAL);
    let charge = linux_packet_skb_truesize(bytes.len());
    let limit = charge * 2 + 1;
    socket.opts.rcvbuf.store(limit as i32, Ordering::Release);
    let stack = crate::NetStack::new();
    let iface = stack.ifaces.register_in_ns(Arc::new(FramingDev::new()), owner.id().as_u64());
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();

    for _ in 0..4 { deliver_packet_ingress_in(&lease, &bytes); }
    assert_eq!(count(&socket), 3, "the crossing frame is admitted before Linux drops the next frame");
    assert_eq!(accounting(&socket), (charge * 3, true));
    assert_eq!(socket.take_packet_statistics(), Ok((crate::uapi::TPACKET_V1,
        PacketStatistics { packets: 4, drops: 1, freeze_queue_count: 0 })));
    assert_eq!(socket.take_packet_statistics(), Ok((crate::uapi::TPACKET_V1,
        PacketStatistics::default())), "PACKET_STATISTICS is clear-on-read");

    assert_eq!(take(&socket).len(), 3);
    assert_eq!(accounting(&socket), (0, false));
}

#[test]
fn packet_version_selects_statistics_layout_and_rejects_unknown_values() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let socket = packet(owner.clone(), RAW);
    let non_packet = InetSocket::new_udp_in(owner);
    assert_eq!(socket.packet_version(), Ok(crate::uapi::TPACKET_V1));
    assert_eq!(socket.set_packet_version(crate::uapi::TPACKET_V3), Ok(()));
    assert_eq!(socket.packet_version(), Ok(crate::uapi::TPACKET_V3));
    assert_eq!(socket.set_packet_version(3), Err(crate::NetError::Einval));
    assert_eq!(non_packet.packet_version(), Err(crate::NetError::Enoprotoopt));
    assert_eq!(non_packet.take_packet_statistics(), Err(crate::NetError::Enoprotoopt));
}

#[test]
fn packet_send_on_loopback_has_one_raw_multicast_receive_view() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let sender = packet(owner.clone(), RAW);
    let observer = packet(owner.clone(), RAW);
    let stack = crate::NetStack::new();
    let loopback = Arc::new(crate::LoopbackDev::new());
    let iface = stack.ifaces.register_in_ns(loopback.clone(), owner.id().as_u64());
    let egress = stack.ifaces.acquire_egress_in_ns(iface, owner.id().as_u64()).unwrap();
    let wire = frame(crate::MacAddr::BROADCAST.0);

    egress.xmit_raw_from(&wire, Some(packet_origin(&sender))).unwrap();
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();
    stack.drain_loopback_in(&lease, &loopback);

    let sender_rows = take(&sender);
    assert_eq!(sender_rows.len(), 1);
    assert_eq!(sender_rows[0].addr.pkttype, crate::uapi::PACKET_MULTICAST);
    assert_eq!(sender_rows[0].payload, wire);
    let observer_rows = take(&observer);
    assert_eq!(observer_rows.len(), 2);
    assert_eq!(observer_rows.iter().map(|row| row.addr.pkttype).collect::<Vec<_>>(),
        [crate::uapi::PACKET_OUTGOING, crate::uapi::PACKET_MULTICAST]);
    assert!(observer_rows.iter().all(|row| row.payload == wire));
    assert!(observer_rows.iter().all(|row| row.addr.hatype == crate::uapi::ARPHRD_LOOPBACK));
}

#[test]
fn invalid_raw_frame_is_rejected_before_outgoing_publication() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let observer = packet(owner.clone(), RAW);
    let stack = crate::NetStack::new();
    let iface = stack.ifaces.register_in_ns(Arc::new(FramingDev::new()), owner.id().as_u64());
    let egress = stack.ifaces.acquire_egress_in_ns(iface, owner.id().as_u64()).unwrap();

    assert_eq!(egress.xmit_raw(&[0; 13]), Err(crate::NetError::Einval));
    assert_eq!(count(&observer), 0);
}

#[test]
fn namespace_teardown_closes_packet_socket_and_releases_registry_state() {
    let _guard = crate::net_ns::test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let owner = crate::net_ns::test_support::allocate_namespace();
    let id = owner.id();
    let socket = packet(owner.clone(), RAW);
    let stack = crate::NetStack::new();

    assert!(!socket.released.load(Ordering::Acquire));
    let poll_generation = socket.poll_subs.generation();
    assert!(crate::net_ns::destroy_namespace_into(&stack, id.as_u64()));
    assert!(socket.released.load(Ordering::Acquire));
    assert!(socket.read_shut.load(Ordering::Acquire));
    assert!(socket.poll_subs.generation() > poll_generation,
        "namespace teardown wakes packet poll observers");
    drop(socket);
    drop(owner);
    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    crate::net_ns::test_support::finish_claimed(&stack, &claimed);
}
