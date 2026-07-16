use super::*;

const TEST_RING_BLOCK_SIZE: u32 = 4096;
const TEST_RING_FRAME_SIZE: u32 = 256;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use crate::bpf_filter::{FilterContext, FilterKind, FilterProgram,
                        install_bpf_filter_context_runner};

const RAW: u8 = 3;
const LOCAL: [u8; 6] = [2, 9, 8, 7, 6, 5];

struct FanoutDev;

impl crate::NetDev for FanoutDev {
    fn name(&self) -> &str { "fanout0" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr(LOCAL) }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, _pkt: crate::Pkt) -> crate::NetResult<()> { Ok(()) }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
}

fn socket(owner: network_namespace::NetworkNamespaceRef) -> Arc<InetSocket> {
    Arc::new(InetSocket::new_packet_in(crate::eth_p::ALL, RAW, owner))
}

fn request(id: u16, mode: u8, flags: u16, max: u32) -> PacketFanoutRequest {
    PacketFanoutRequest { id, type_flags: mode as u16 | flags, max_num_members: max }
}

fn frame(flow: u16) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; 14 + 20 + 8];
    bytes[..6].copy_from_slice(&LOCAL);
    bytes[6..12].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    bytes[12..14].copy_from_slice(&crate::eth_p::IPV4.to_be_bytes());
    bytes[14] = 0x45;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&[10, 0, 0, 1]);
    bytes[30..34].copy_from_slice(&[10, 0, 0, 2]);
    bytes[34..36].copy_from_slice(&flow.to_be_bytes());
    bytes[36..38].copy_from_slice(&53u16.to_be_bytes());
    bytes
}

fn count(socket: &InetSocket) -> usize {
    let kind = socket.kind.lock();
    let SockKind::Packet { rx, .. } = &*kind else { return 0 };
    let count = rx.lock().len();
    count
}

fn ingress(owner: &network_namespace::NetworkNamespaceRef) -> (crate::NetStack, crate::IngressLease) {
    let stack = crate::NetStack::new();
    let iface = stack.ifaces.register_in_ns(Arc::new(FanoutDev), owner.id().as_u64());
    let lease = stack.ifaces.acquire_ingress(iface).unwrap();
    (stack, lease)
}

fn filter_index(_kind: FilterKind, insns: &[u8], _context: FilterContext<'_>) -> u32 {
    u32::from_ne_bytes(insns.try_into().unwrap())
}

#[test]
fn lb_delivers_exactly_once_and_rotates_members() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let a = socket(owner.clone());
    let b = socket(owner.clone());
    a.join_packet_fanout(request(101, crate::uapi::PACKET_FANOUT_LB, 0, 0)).unwrap();
    b.join_packet_fanout(request(101, crate::uapi::PACKET_FANOUT_LB, 0, 0)).unwrap();
    let (_stack, lease) = ingress(&owner);
    for flow in 0..6 { deliver_packet_ingress_in(&lease, &frame(flow)); }
    assert_eq!((count(&a), count(&b)), (3, 3));
}

#[test]
fn protocol_bound_outgoing_does_not_advance_lb_selector() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let a = Arc::new(InetSocket::new_packet_in(crate::eth_p::IPV4, RAW, owner.clone()));
    let b = Arc::new(InetSocket::new_packet_in(crate::eth_p::IPV4, RAW, owner.clone()));
    a.join_packet_fanout(request(126, crate::uapi::PACKET_FANOUT_LB, 0, 0)).unwrap();
    b.join_packet_fanout(request(126, crate::uapi::PACKET_FANOUT_LB, 0, 0)).unwrap();
    let (stack, lease) = ingress(&owner);
    let egress = stack.ifaces.acquire_egress_in_ns(lease.iface(), owner.id().as_u64()).unwrap();

    egress.xmit_raw(&frame(1)).unwrap();
    assert_eq!((count(&a), count(&b)), (0, 0));
    deliver_packet_ingress_in(&lease, &frame(2));
    assert_eq!((count(&a), count(&b)), (0, 1));
}

#[test]
fn packet_origin_suppresses_the_entire_fanout_group() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let a = socket(owner.clone());
    let b = socket(owner.clone());
    let observer = socket(owner.clone());
    register_packet(&observer);
    a.join_packet_fanout(request(116, crate::uapi::PACKET_FANOUT_LB, 0, 0)).unwrap();
    b.join_packet_fanout(request(116, crate::uapi::PACKET_FANOUT_LB, 0, 0)).unwrap();
    let (stack, lease) = ingress(&owner);
    let egress = stack.ifaces.acquire_egress_in_ns(lease.iface(), owner.id().as_u64()).unwrap();
    egress.xmit_raw_from(&frame(1), Some(packet_origin(&a))).unwrap();
    assert_eq!((count(&a), count(&b)), (0, 0));
    assert_eq!(count(&observer), 1);
}

#[test]
fn fanout_hook_ignores_only_the_group_outgoing_flag() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let sender = socket(owner.clone());
    let observer = socket(owner.clone());
    register_packet(&observer);
    let a = socket(owner.clone());
    let b = socket(owner.clone());
    a.join_packet_fanout(request(117, crate::uapi::PACKET_FANOUT_LB, 0, 0)).unwrap();
    b.join_packet_fanout(request(117, crate::uapi::PACKET_FANOUT_LB, 0, 0)).unwrap();
    b.set_packet_ignore_outgoing(true).unwrap();
    let (stack, lease) = ingress(&owner);
    let egress = stack.ifaces.acquire_egress_in_ns(lease.iface(), owner.id().as_u64()).unwrap();
    egress.xmit_raw_from(&frame(2), Some(packet_origin(&sender))).unwrap();
    assert_eq!((count(&a), count(&b)), (0, 1));
    assert_eq!(count(&observer), 1);

    let c = socket(owner.clone());
    let d = socket(owner.clone());
    let flag = crate::uapi::PACKET_FANOUT_FLAG_IGNORE_OUTGOING;
    c.join_packet_fanout(request(118, crate::uapi::PACKET_FANOUT_LB, flag, 0)).unwrap();
    d.join_packet_fanout(request(118, crate::uapi::PACKET_FANOUT_LB, flag, 0)).unwrap();
    egress.xmit_raw_from(&frame(3), Some(packet_origin(&sender))).unwrap();
    assert_eq!((count(&c), count(&d)), (0, 0));
    assert_eq!(count(&observer), 2);
}

#[test]
fn member_release_uses_linux_last_member_swap_order() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let a = socket(owner.clone());
    let b = socket(owner.clone());
    let c = socket(owner.clone());
    for socket in [&a, &b, &c] {
        socket.join_packet_fanout(request(119, crate::uapi::PACKET_FANOUT_LB, 0, 0)).unwrap();
    }
    a.release_file();
    let (_stack, lease) = ingress(&owner);
    deliver_packet_ingress_in(&lease, &frame(4));
    assert_eq!((count(&b), count(&c)), (1, 0));
}

#[test]
fn ring_reconfiguration_unlinks_and_appends_the_member() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let a = socket(owner.clone());
    let b = socket(owner.clone());
    let c = socket(owner.clone());
    for socket in [&a, &b, &c] {
        socket.join_packet_fanout(request(120, crate::uapi::PACKET_FANOUT_LB, 0, 0)).unwrap();
    }
    b.set_packet_ring(PacketRingKind::Tx, PacketRingRequest {
        block_size: TEST_RING_BLOCK_SIZE, block_nr: 1,
        frame_size: TEST_RING_FRAME_SIZE,
        frame_nr: TEST_RING_BLOCK_SIZE / TEST_RING_FRAME_SIZE,
        ..PacketRingRequest::default()
    }).unwrap();
    let (_stack, lease) = ingress(&owner);
    deliver_packet_ingress_in(&lease, &frame(5));
    assert_eq!((count(&a), count(&b), count(&c)), (0, 0, 1));
}

#[test]
fn rejected_ring_reconfiguration_preserves_member_order() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let a = socket(owner.clone());
    let b = socket(owner.clone());
    let c = socket(owner.clone());
    for socket in [&a, &b, &c] {
        socket.join_packet_fanout(request(125, crate::uapi::PACKET_FANOUT_LB, 0, 0)).unwrap();
    }
    let ring = PacketRingRequest {
        block_size: TEST_RING_BLOCK_SIZE, block_nr: 1,
        frame_size: TEST_RING_FRAME_SIZE,
        frame_nr: TEST_RING_BLOCK_SIZE / TEST_RING_FRAME_SIZE,
        ..PacketRingRequest::default()
    };
    b.set_packet_ring(PacketRingKind::Tx, ring).unwrap();
    a.release_file();
    assert_eq!(b.set_packet_ring(PacketRingKind::Tx, ring), Err(crate::NetError::Ebusy));
    let (_stack, lease) = ingress(&owner);
    deliver_packet_ingress_in(&lease, &frame(6));
    assert_eq!((count(&b), count(&c)), (0, 1));
}

#[test]
fn fixed_selectors_use_swap_order_and_preserve_group_bpf() {
    install_bpf_filter_context_runner(filter_index);
    let owner = crate::net_ns::test_support::allocate_namespace();
    let (_stack, lease) = ingress(&owner);
    for (id, mode) in [(121, crate::uapi::PACKET_FANOUT_CPU),
                       (122, crate::uapi::PACKET_FANOUT_QM),
                       (123, crate::uapi::PACKET_FANOUT_CBPF),
                       (124, crate::uapi::PACKET_FANOUT_EBPF)]
    {
        let a = socket(owner.clone());
        let b = socket(owner.clone());
        let c = socket(owner.clone());
        for socket in [&a, &b, &c] {
            socket.join_packet_fanout(request(id, mode, 0, 0)).unwrap();
        }
        if matches!(mode, crate::uapi::PACKET_FANOUT_CBPF | crate::uapi::PACKET_FANOUT_EBPF) {
            a.set_packet_fanout_data(FilterProgram {
                kind: if mode == crate::uapi::PACKET_FANOUT_CBPF {
                    FilterKind::Classic
                } else { FilterKind::Ebpf },
                insns: 0u32.to_ne_bytes().to_vec(),
            }).unwrap();
        }
        a.release_file();
        deliver_packet_ingress_meta_in(&lease, &frame(id), crate::PacketRxMetadata {
            queue: 0, ..crate::PacketRxMetadata::default()
        });
        assert_eq!((count(&b), count(&c)), (0, 1), "mode {mode}");
    }
}

#[test]
fn hash_keeps_one_flow_on_one_member() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let a = socket(owner.clone());
    let b = socket(owner.clone());
    a.join_packet_fanout(request(102, crate::uapi::PACKET_FANOUT_HASH, 0, 0)).unwrap();
    b.join_packet_fanout(request(102, crate::uapi::PACKET_FANOUT_HASH, 0, 0)).unwrap();
    let (_stack, lease) = ingress(&owner);
    for _ in 0..5 { deliver_packet_ingress_in(&lease, &frame(4000)); }
    assert!(matches!((count(&a), count(&b)), (5, 0) | (0, 5)));
}

#[test]
fn group_key_is_namespace_scoped_and_configuration_is_exact() {
    let one = crate::net_ns::test_support::allocate_namespace();
    let two = crate::net_ns::test_support::allocate_namespace();
    let a = socket(one.clone());
    let incompatible = socket(one);
    let foreign = socket(two);
    a.join_packet_fanout(request(103, crate::uapi::PACKET_FANOUT_CPU, 0, 2)).unwrap();
    assert_eq!(incompatible.join_packet_fanout(request(
        103, crate::uapi::PACKET_FANOUT_QM, 0, 2)), Err(crate::NetError::Einval));
    foreign.join_packet_fanout(request(103, crate::uapi::PACKET_FANOUT_QM, 0, 2)).unwrap();
}

#[test]
fn capacity_unique_id_and_duplicate_join_follow_linux_errors() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let a = socket(owner.clone());
    let b = socket(owner.clone());
    a.join_packet_fanout(request(104, crate::uapi::PACKET_FANOUT_LB, 0, 1)).unwrap();
    assert_eq!(a.join_packet_fanout(request(105, crate::uapi::PACKET_FANOUT_LB, 0, 1)),
        Err(crate::NetError::Ealready));
    assert_eq!(b.join_packet_fanout(request(104, crate::uapi::PACKET_FANOUT_LB, 0, 1)),
        Err(crate::NetError::Enospc));
    let occupied_zero = socket(owner.clone());
    occupied_zero.join_packet_fanout(request(
        0, crate::uapi::PACKET_FANOUT_HASH, 0, 1)).unwrap();
    let unique = socket(owner);
    unique.join_packet_fanout(request(0, crate::uapi::PACKET_FANOUT_HASH,
        crate::uapi::PACKET_FANOUT_FLAG_UNIQUEID, 0)).unwrap();
    assert_ne!(unique.packet_fanout_value().unwrap(), 0);
    let extended = socket(crate::net_ns::test_support::allocate_namespace());
    extended.join_packet_fanout(request(
        1, crate::uapi::PACKET_FANOUT_HASH, 0, 257)).unwrap();
    let excessive = socket(crate::net_ns::test_support::allocate_namespace());
    assert_eq!(excessive.join_packet_fanout(request(1, crate::uapi::PACKET_FANOUT_HASH,
        0, crate::uapi::PACKET_FANOUT_MAX + 1)), Err(crate::NetError::Einval));
}

#[test]
fn rollover_uses_queue_pressure_and_accounts_selection() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let pressured = socket(owner.clone());
    let ready = socket(owner.clone());
    pressured.opts.rcvbuf.store(32, Ordering::Release);
    let flags = crate::uapi::PACKET_FANOUT_FLAG_ROLLOVER;
    ready.join_packet_fanout(request(106, crate::uapi::PACKET_FANOUT_LB, flags, 0)).unwrap();
    pressured.join_packet_fanout(request(106, crate::uapi::PACKET_FANOUT_LB, flags, 0)).unwrap();
    let (_stack, lease) = ingress(&owner);
    deliver_packet_ingress_in(&lease, &frame(1));
    assert_eq!((count(&pressured), count(&ready)), (0, 1));
    assert_eq!(pressured.packet_rollover_statistics().unwrap(), PacketRolloverStatistics {
        all: 1, huge: 0, failed: 0,
    });
}

#[test]
fn final_release_removes_membership_and_empty_group() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let first = socket(owner.clone());
    first.join_packet_fanout(request(107, crate::uapi::PACKET_FANOUT_LB, 0, 1)).unwrap();
    assert_eq!(first.bind_packet(0, crate::eth_p::IPV4), Err(crate::NetError::Einval));
    first.release_file();
    assert!(!first.packet_in_fanout());
    let replacement = socket(owner);
    replacement.join_packet_fanout(request(107, crate::uapi::PACKET_FANOUT_HASH, 0, 2)).unwrap();
}

#[test]
fn final_release_waits_for_selected_delivery_and_blocks_late_delivery() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let socket = socket(owner);
    socket.join_packet_fanout(request(115, crate::uapi::PACKET_FANOUT_LB, 0, 1)).unwrap();
    let member = packet_fanout_membership(&socket).unwrap();
    let entered = Arc::new(std::sync::Barrier::new(2));
    let leave = Arc::new(std::sync::Barrier::new(2));
    let delivery = {
        let member = member.clone();
        let entered = entered.clone();
        let leave = leave.clone();
        std::thread::spawn(move || with_packet_fanout_socket(&member, |_| {
            entered.wait();
            leave.wait();
        }))
    };
    entered.wait();
    let (closed_tx, closed_rx) = std::sync::mpsc::channel();
    let closing = {
        let socket = socket.clone();
        std::thread::spawn(move || {
            socket.release_packet_fanout();
            closed_tx.send(()).unwrap();
        })
    };
    while socket.packet_in_fanout() { std::thread::yield_now(); }
    assert_eq!(closed_rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty));
    leave.wait();
    assert!(delivery.join().unwrap().is_some());
    closing.join().unwrap();
    assert_eq!(closed_rx.try_recv(), Ok(()));
    assert!(with_packet_fanout_socket(&member, |_| ()).is_none());
}

#[test]
fn cpu_qm_random_and_bpf_modes_each_choose_one_member() {
    install_bpf_filter_context_runner(filter_index);
    let owner = crate::net_ns::test_support::allocate_namespace();
    let (_stack, lease) = ingress(&owner);
    for (id, mode) in [(108, crate::uapi::PACKET_FANOUT_CPU),
                       (109, crate::uapi::PACKET_FANOUT_QM),
                       (110, crate::uapi::PACKET_FANOUT_RND),
                       (111, crate::uapi::PACKET_FANOUT_CBPF),
                       (112, crate::uapi::PACKET_FANOUT_EBPF)]
    {
        let a = socket(owner.clone());
        let b = socket(owner.clone());
        a.join_packet_fanout(request(id, mode, 0, 0)).unwrap();
        b.join_packet_fanout(request(id, mode, 0, 0)).unwrap();
        if matches!(mode, crate::uapi::PACKET_FANOUT_CBPF | crate::uapi::PACKET_FANOUT_EBPF) {
            a.set_packet_fanout_data(FilterProgram {
                kind: if mode == crate::uapi::PACKET_FANOUT_CBPF {
                    FilterKind::Classic
                } else { FilterKind::Ebpf },
                insns: 1u32.to_ne_bytes().to_vec(),
            }).unwrap();
        }
        deliver_packet_ingress_meta_in(&lease, &frame(id), crate::PacketRxMetadata {
            queue: 1, ..crate::PacketRxMetadata::default()
        });
        assert_eq!(count(&a) + count(&b), 1, "mode {mode}");
        if matches!(mode, crate::uapi::PACKET_FANOUT_QM | crate::uapi::PACKET_FANOUT_CBPF
            | crate::uapi::PACKET_FANOUT_EBPF)
        { assert_eq!((count(&a), count(&b)), (0, 1), "mode {mode}"); }
    }
}

#[test]
fn rollover_mode_skips_a_pressured_first_member() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let pressured = socket(owner.clone());
    let ready = socket(owner.clone());
    pressured.opts.rcvbuf.store(32, Ordering::Release);
    pressured.join_packet_fanout(request(
        113, crate::uapi::PACKET_FANOUT_ROLLOVER, 0, 0)).unwrap();
    ready.join_packet_fanout(request(
        113, crate::uapi::PACKET_FANOUT_ROLLOVER, 0, 0)).unwrap();
    let (_stack, lease) = ingress(&owner);
    deliver_packet_ingress_in(&lease, &frame(1));
    assert_eq!((count(&pressured), count(&ready)), (0, 1));
}

fn ipv4_fragment(id: u16, offset: u16, more: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; 14 + 20 + payload.len()];
    bytes[..6].copy_from_slice(&LOCAL);
    bytes[6..12].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    bytes[12..14].copy_from_slice(&crate::eth_p::IPV4.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    bytes[18..20].copy_from_slice(&id.to_be_bytes());
    let fragment = offset | if more { 0x2000 } else { 0 };
    bytes[20..22].copy_from_slice(&fragment.to_be_bytes());
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&[10, 0, 0, 1]);
    bytes[30..34].copy_from_slice(&[10, 0, 0, 2]);
    bytes[34..].copy_from_slice(payload);
    bytes
}

#[test]
fn defrag_group_receives_one_rebuilt_ipv4_packet() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let socket = socket(owner.clone());
    socket.join_packet_fanout(request(114, crate::uapi::PACKET_FANOUT_HASH,
        crate::uapi::PACKET_FANOUT_FLAG_DEFRAG, 0)).unwrap();
    let (_stack, lease) = ingress(&owner);
    deliver_packet_ingress_in(&lease, &ipv4_fragment(55, 0, true, b"abcdefgh"));
    assert_eq!(count(&socket), 0);
    deliver_packet_ingress_in(&lease, &ipv4_fragment(55, 1, false, b"ijklmnop"));
    assert_eq!(count(&socket), 1);
    let kind = socket.kind.lock();
    let SockKind::Packet { rx, .. } = &*kind else { panic!("packet socket") };
    let limit = socket.opts.rcvbuf.load(Ordering::Acquire).max(0) as usize;
    let rebuilt = rx.lock().take_all(limit).remove(0).payload;
    assert_eq!(rebuilt.len(), 14 + 20 + 16);
    assert_eq!(&rebuilt[34..], b"abcdefghijklmnop");
    assert_eq!(u16::from_be_bytes([rebuilt[20], rebuilt[21]]), 0);
}
