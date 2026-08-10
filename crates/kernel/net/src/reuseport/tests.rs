// Verified reuseport contract: the attach/detach errno ladders, one group per
// bind key, departure on close, and program-driven selection overriding the
// per-flow hash.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};
use sync::{Socket as StackLockClass, Spinlock};
use syscall::errno::Errno;

use super::slot::{self, ReuseportSlot};
use super::{Select, SelectInput};
use crate::bpf_filter::{install_bpf_filter_runner, FilterKind, FilterProgram, SocketFilter};
use crate::sock::InetSocket;
use crate::{Ipv4Addr, NetIfaceId, NetStack, SocketError, UdpRxQueue};

const PORT: u16 = 49_311;
const OTHER_PORT: u16 = 49_312;
const SOURCE_PORT: u16 = 41_777;

/// Selection-program stand-in whose whole body is the index it returns.
fn index_runner(_kind: FilterKind, insns: &[u8], _packet: &[u8]) -> u32 {
    u32::from_ne_bytes(insns.try_into().expect("index program is one u32"))
}

fn prog(index: u32) -> FilterProgram {
    FilterProgram { kind: FilterKind::Ebpf, insns: index.to_ne_bytes().to_vec() }
}

fn bind4(stack: &NetStack, port: u16, reuseport: bool) -> Arc<UdpRxQueue> {
    stack.bind_udp_socket(
        Ipv4Addr::LOOPBACK, port, None, Arc::new(SocketError::new()),
        Arc::new(AtomicI32::new(0)), Arc::new(AtomicI32::new(i32::from(reuseport))),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), 0,
        Arc::new(Spinlock::<Option<(Ipv4Addr, u16)>, StackLockClass>::new(None)),
        Arc::new(SocketFilter::new()), Arc::new(crate::mcast_filter::SocketMcast::new()),
    ).expect("reuseport bind shares the key")
}

fn join4(stack: &NetStack, endpoint: &Arc<UdpRxQueue>) -> ReuseportSlot {
    let member = slot::new_slot();
    stack.join_udp4_reuseport(endpoint, &member);
    member
}

fn udp_socket() -> Arc<InetSocket> { Arc::new(InetSocket::new_udp()) }

#[test]
fn attach_on_an_unhashed_socket_needs_so_reuseport_then_builds_one_member_group() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let sock = udp_socket();
    assert_eq!(super::attach_prog(&sock, super::GroupProgram::bare(prog(0))), Err(Errno::Einval));
    assert!(super::group_of(&sock).is_none());

    sock.opts.base.reuseport.store(1, Ordering::Release);
    assert_eq!(super::attach_prog(&sock, super::GroupProgram::bare(prog(0))), Ok(()));
    let group = super::group_of(&sock).expect("attach allocated the group");
    assert!(group.has_prog());
    assert_eq!(group.num_socks(), 1);

    // A second attach replaces the program inside the same group.
    assert_eq!(super::attach_prog(&sock, super::GroupProgram::bare(prog(1))), Ok(()));
    assert!(Arc::ptr_eq(&super::group_of(&sock).unwrap(), &group));
    assert_eq!(group.num_socks(), 1);
}

#[test]
fn attach_on_a_hashed_socket_bound_without_so_reuseport_is_einval() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let endpoint = bind4(&stack, PORT, false);
    let sock = udp_socket();
    *sock.udp4.lock() = Some(endpoint);
    assert!(super::is_hashed(&sock));

    assert_eq!(super::attach_prog(&sock, super::GroupProgram::bare(prog(0))), Err(Errno::Einval));
    // Setting the option after the bind does not retroactively create a group.
    sock.opts.base.reuseport.store(1, Ordering::Release);
    assert_eq!(super::attach_prog(&sock, super::GroupProgram::bare(prog(0))), Err(Errno::Einval));
    assert!(super::group_of(&sock).is_none());
}

#[test]
fn detach_reports_einval_without_so_reuseport_and_enoent_once_it_is_set() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let sock = udp_socket();
    assert_eq!(super::detach_prog(&sock), Err(Errno::Einval));

    sock.opts.base.reuseport.store(1, Ordering::Release);
    assert_eq!(super::detach_prog(&sock), Err(Errno::Enoent));

    super::alloc_for_unhashed(&sock).expect("SO_REUSEPORT allows the group");
    // A group carrying no program is still ENOENT, not success.
    assert_eq!(super::detach_prog(&sock), Err(Errno::Enoent));

    super::attach_prog(&sock, super::GroupProgram::bare(prog(0))).unwrap();
    assert_eq!(super::detach_prog(&sock), Ok(()));
    assert_eq!(super::detach_prog(&sock), Err(Errno::Enoent));
    assert!(!super::group_of(&sock).unwrap().has_prog());
}

#[test]
fn an_unhashed_socket_cannot_detach_from_a_group_holding_shutdown_members() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let sock = udp_socket();
    sock.opts.base.reuseport.store(1, Ordering::Release);
    let group = super::alloc_for_unhashed(&sock).unwrap();
    super::attach_prog(&sock, super::GroupProgram::bare(prog(0))).unwrap();

    group.note_closed_sock();
    assert_eq!(super::detach_prog(&sock), Err(Errno::Enoent));
    assert!(group.has_prog());

    group.release_closed_sock();
    assert_eq!(super::detach_prog(&sock), Ok(()));
}

#[test]
fn a_prebind_group_survives_a_bind_that_finds_no_key_mate() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let sock = udp_socket();
    sock.opts.base.reuseport.store(1, Ordering::Release);
    let group = super::alloc_for_unhashed(&sock).unwrap();
    super::attach_prog(&sock, super::GroupProgram::bare(prog(2))).unwrap();

    let endpoint = bind4(&stack, PORT, true);
    stack.join_udp4_reuseport(&endpoint, &sock.reuseport_group);
    assert!(Arc::ptr_eq(&super::group_of(&sock).unwrap(), &group));
    assert!(Arc::ptr_eq(&slot::group(&endpoint.reuseport_group).unwrap(), &group));
    assert!(group.has_prog());
}

#[test]
fn sockets_binding_one_key_share_a_group_and_leave_it_when_closed() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let first = bind4(&stack, PORT, true);
    let first_member = join4(&stack, &first);
    let second = bind4(&stack, PORT, true);
    let second_member = join4(&stack, &second);

    let group = slot::group(&first_member).expect("first socket allocated the group");
    assert!(Arc::ptr_eq(&slot::group(&second_member).unwrap(), &group));
    assert!(Arc::ptr_eq(&slot::group(&first.reuseport_group).unwrap(), &group));
    assert!(Arc::ptr_eq(&slot::group(&second.reuseport_group).unwrap(), &group));
    assert_eq!(group.num_socks(), 2);

    // A different bind key never joins.
    let elsewhere = bind4(&stack, OTHER_PORT, true);
    let elsewhere_member = join4(&stack, &elsewhere);
    assert!(!Arc::ptr_eq(&slot::group(&elsewhere_member).unwrap(), &group));

    // Dropping the socket's cell is what removes it, exactly as a close does.
    drop(second_member);
    assert_eq!(group.num_socks(), 1);
    slot::leave(&first_member);
    assert_eq!(group.num_socks(), 0);
    assert!(slot::group(&first_member).is_none());
}

#[test]
fn an_endpoint_bound_without_so_reuseport_never_joins_a_group() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let endpoint = bind4(&stack, PORT, false);
    let member = join4(&stack, &endpoint);
    assert!(slot::group(&member).is_none());
    assert!(slot::group(&endpoint.reuseport_group).is_none());
}

fn selection_group(stack: &NetStack)
    -> ([Arc<UdpRxQueue>; 3], Arc<super::ReuseportGroup>, [ReuseportSlot; 3])
{
    let endpoints = [bind4(stack, PORT, true), bind4(stack, PORT, true), bind4(stack, PORT, true)];
    let members = [join4(stack, &endpoints[0]), join4(stack, &endpoints[1]),
                   join4(stack, &endpoints[2])];
    let group = slot::group(&members[0]).expect("the bind key allocated one group");
    assert_eq!(group.num_socks(), 3);
    (endpoints, group, members)
}

fn demux_one(stack: &NetStack, iface: NetIfaceId, sport: u16, payload: &[u8])
    -> Arc<UdpRxQueue>
{
    let selected = stack.udp_demux_in(0, Ipv4Addr::LOOPBACK, sport, Ipv4Addr::LOOPBACK, PORT,
        iface, payload);
    assert_eq!(selected.len(), 1);
    selected[0].clone()
}

#[test]
fn an_attached_program_names_the_member_and_a_bad_result_falls_back_to_the_hash() {
    let _domain = crate::hosted_fixture::init_net_domain();
    install_bpf_filter_runner(index_runner);
    let stack = NetStack::new();
    let (iface, _loopback) = stack.register_loopback();
    let (endpoints, group, _members) = selection_group(&stack);

    // With no program the flow hash decides, and it decides the same way twice.
    let hashed = demux_one(&stack, iface, SOURCE_PORT, b"body");
    assert!(Arc::ptr_eq(&demux_one(&stack, iface, SOURCE_PORT, b"body"), &hashed));

    // Every member index the program can name is honoured, hash regardless.
    for index in 0..endpoints.len() {
        group.attach_prog(super::GroupProgram::bare(prog(index as u32)));
        let selected = demux_one(&stack, iface, SOURCE_PORT, b"body");
        assert!(Arc::ptr_eq(&selected, &endpoints[index]), "program selected index {index}");
    }

    // A result at or past the member count selects nothing, so the hash stands.
    group.attach_prog(super::GroupProgram::bare(prog(endpoints.len() as u32)));
    assert!(Arc::ptr_eq(&demux_one(&stack, iface, SOURCE_PORT, b"body"), &hashed));
    group.attach_prog(super::GroupProgram::bare(prog(u32::MAX)));
    assert!(Arc::ptr_eq(&demux_one(&stack, iface, SOURCE_PORT, b"body"), &hashed));

    // Detaching restores the hash distribution for every flow.
    group.detach_prog().unwrap();
    for sport in SOURCE_PORT..SOURCE_PORT + 8 {
        let first = demux_one(&stack, iface, sport, b"body");
        assert!(Arc::ptr_eq(&demux_one(&stack, iface, sport, b"body"), &first));
    }
}

/// A packet whose first `hdr_len` bytes are the transport header.
fn input(members_len: usize, transport: &[u8], hdr_len: usize) -> SelectInput<'_> {
    SelectInput { hash: 7, members_len, transport, hdr_len,
        eth_protocol: crate::addr::eth_p::IPV4, ip_protocol: crate::addr::IpProto::Udp as u8,
        family: crate::socket_args::AF_INET as u16 }
}

#[test]
fn a_classic_program_names_the_member_and_a_bad_index_leaves_the_hash() {
    let _domain = crate::hosted_fixture::init_net_domain();
    // The runner echoes its program body, so both call shapes must reach it.
    install_bpf_filter_runner(index_runner);
    let group = super::ReuseportGroup::new();
    assert_eq!(group.select(input(4, b"body", 0), |_| None), Select::Hash, "no program selects nothing");

    group.attach_prog(super::GroupProgram::bare(prog(3)));
    assert_eq!(group.select(input(4, b"body", 0), |_| None), Select::Member(3));
    assert_eq!(group.select(input(4, &[], 0), |_| None), Select::Member(3),
        "a caller holding no bytes still runs the program");
    assert_eq!(group.select(input(3, b"body", 0), |_| None), Select::Hash,
        "index at the member count is refused");
    assert_eq!(group.select(input(0, b"body", 0), |_| None), Select::Hash,
        "an empty member set selects nothing");
}

#[test]
fn the_classic_flavour_sees_the_packet_past_its_transport_header() {
    let _domain = crate::hosted_fixture::init_net_domain();
    // This runner answers with the first byte the program was shown, so the
    // result names where the data pointer was left.
    fn first_byte(_kind: FilterKind, _insns: &[u8], packet: &[u8]) -> u32 {
        u32::from(packet.first().copied().unwrap_or(0xff))
    }
    install_bpf_filter_runner(first_byte);
    let group = super::ReuseportGroup::new();
    group.attach_prog(super::GroupProgram::bare(FilterProgram {
        kind: FilterKind::Classic, insns: alloc::vec![0],
    }));
    let datagram = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x02, 0x03];
    assert_eq!(group.select(input(4, &datagram, crate::udp::UDP_HDR_LEN), |_| None), Select::Member(2),
        "the classic flavour reads from the payload, not the header");
    assert_eq!(group.select(input(4, &datagram, 0), |_| None), Select::Hash,
        "reading from the header would have produced an out-of-range index");
    // A header longer than the packet leaves nothing to read rather than
    // reading past the end.
    assert_eq!(group.select(input(4, &datagram, 64), |_| None), Select::Hash);
}

#[test]
fn the_reuseport_flavour_reads_the_metadata_and_can_refuse_the_packet() {
    let _domain = crate::hosted_fixture::init_net_domain();
    static SEEN: Spinlock<Option<(usize, u16, u8, bool, u32)>, StackLockClass> =
        Spinlock::new(None);
    fn record(insns: &[u8], _maps: &[vfs::InodeRef],
              _runner: security::bpf::map::sockarray::RunnerState,
              ctx: crate::bpf_filter::ReuseportContext<'_>)
        -> crate::bpf_filter::ReuseportVerdict
    {
        *SEEN.lock() = Some((ctx.packet.len(), ctx.eth_protocol, ctx.ip_protocol,
            ctx.bind_inany, ctx.hash));
        crate::bpf_filter::ReuseportVerdict { action: u32::from(insns[0]), selected: None }
    }
    crate::bpf_filter::install_bpf_reuseport_runner(record);
    let group = super::ReuseportGroup::new();
    group.attach_prog(super::GroupProgram::bare(FilterProgram {
        kind: FilterKind::SkReuseport, insns: alloc::vec![crate::bpf_filter::SK_PASS as u8],
    }));
    let datagram = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];

    // A passing program that named no member leaves the hash distribution.
    assert_eq!(group.select(input(4, &datagram, crate::udp::UDP_HDR_LEN), |_| None), Select::Hash);
    // The context begins AT the transport header, unlike the classic flavour.
    assert_eq!(*SEEN.lock(), Some((datagram.len(), crate::addr::eth_p::IPV4,
        crate::addr::IpProto::Udp as u8, false, 7)));

    group.note_bind_inany(false);
    assert!(!group.bind_inany());
    group.note_bind_inany(true);
    let _ = group.select(input(4, &datagram, crate::udp::UDP_HDR_LEN), |_| None);
    assert_eq!(SEEN.lock().map(|seen| seen.3), Some(true));

    group.attach_prog(super::GroupProgram::bare(FilterProgram {
        kind: FilterKind::SkReuseport, insns: alloc::vec![crate::bpf_filter::SK_DROP as u8],
    }));
    assert_eq!(group.select(input(4, &datagram, crate::udp::UDP_HDR_LEN), |_| None), Select::Drop);
}

#[test]
fn a_refused_packet_reaches_no_member_and_a_hash_result_reaches_one() {
    assert_eq!(Select::Drop.index(7, 4), None);
    assert_eq!(Select::Member(2).index(7, 4), Some(2));
    assert_eq!(Select::Hash.index(7, 4), Some(3));
    assert_eq!(Select::Hash.index(7, 0), None, "no member can take a packet");
}
