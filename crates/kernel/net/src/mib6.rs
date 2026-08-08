// Per-network-namespace IPv6 MIB state.  Procfs only renders this canonical
// state; receive and transmit owners name the event they have just observed.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::Deref;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Socket as MibLockClass, Spinlock};

const INITIAL_NET_NS: u64 = 0;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Ip6Mib {
    InReceives, InHdrErrors, InTooBigErrors, InNoRoutes, InAddrErrors, InUnknownProtos,
    InTruncatedPkts, InDiscards, InDelivers, OutForwDatagrams, OutRequests, OutDiscards,
    OutNoRoutes, ReasmTimeout, ReasmReqds, ReasmOks, ReasmFails, FragOks, FragFails,
    FragCreates, InMcastPkts, OutMcastPkts, InOctets, OutOctets, InMcastOctets,
    OutMcastOctets, InBcastOctets, OutBcastOctets, InNoEctPkts, InEct1Pkts,
    InEct0Pkts, InCePkts, OutTransmits,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Icmp6Mib { InMsgs, InErrors, OutMsgs, OutErrors, InCsumErrors, OutRateLimitHost }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Udp6Mib {
    InDatagrams, NoPorts, InErrors, OutDatagrams, RcvbufErrors, SndbufErrors, InCsumErrors,
    IgnoredMulti, MemErrors,
}

const IP6_COUNTERS: usize = 33;
const ICMP6_COUNTERS: usize = 6;
const UDP6_COUNTERS: usize = 9;
const ICMP6_TYPE_COUNTERS: usize = 512;

impl Ip6Mib { const fn index(self) -> usize { self as usize } }
impl Icmp6Mib { const fn index(self) -> usize { self as usize } }
impl Udp6Mib { const fn index(self) -> usize { self as usize } }

struct Counters {
    ip: [AtomicU64; IP6_COUNTERS],
    icmp: [AtomicU64; ICMP6_COUNTERS],
    udp: [AtomicU64; UDP6_COUNTERS],
    icmp_type: [AtomicU64; ICMP6_TYPE_COUNTERS],
}

impl Counters {
    const fn new() -> Self {
        Self {
            ip: [const { AtomicU64::new(0) }; IP6_COUNTERS],
            icmp: [const { AtomicU64::new(0) }; ICMP6_COUNTERS],
            udp: [const { AtomicU64::new(0) }; UDP6_COUNTERS],
            icmp_type: [const { AtomicU64::new(0) }; ICMP6_TYPE_COUNTERS],
        }
    }
}

struct NamespaceLock(Spinlock<BTreeMap<u64, Arc<Counters>>, MibLockClass>);

impl NamespaceLock {
    const fn new() -> Self { Self(Spinlock::new(BTreeMap::new())) }
    fn lock(&self) -> sync::LockBhGuard<'_, BTreeMap<u64, Arc<Counters>>, MibLockClass,
        sched::bh::SchedBh> { self.0.lock_bh::<sched::bh::SchedBh>() }
}

static INITIAL: Counters = Counters::new();
static NAMESPACES: NamespaceLock = NamespaceLock::new();

enum CounterRef { Initial(&'static Counters), Dynamic(Arc<Counters>) }
impl Deref for CounterRef {
    type Target = Counters;
    fn deref(&self) -> &Counters { match self { Self::Initial(v) => v, Self::Dynamic(v) => v } }
}

fn counters(net_ns: u64) -> CounterRef {
    if net_ns == INITIAL_NET_NS { return CounterRef::Initial(&INITIAL); }
    CounterRef::Dynamic(NAMESPACES.lock().entry(net_ns).or_insert_with(|| Arc::new(Counters::new())).clone())
}

/// Count one IPv6 MIB event. # C: O(log N namespaces)
pub fn bump_ip(net_ns: u64, which: Ip6Mib) {
    counters(net_ns).ip[which.index()].fetch_add(1, Ordering::Relaxed);
}
/// Add `n` IPv6 MIB events. # C: O(log N namespaces)
pub fn add_ip(net_ns: u64, which: Ip6Mib, n: u64) {
    counters(net_ns).ip[which.index()].fetch_add(n, Ordering::Relaxed);
}
/// Read one IPv6 MIB event. # C: O(log N namespaces)
pub fn get_ip(net_ns: u64, which: Ip6Mib) -> u64 {
    counters(net_ns).ip[which.index()].load(Ordering::Relaxed)
}
/// Count one ICMPv6 MIB event. # C: O(log N namespaces)
pub fn bump_icmp(net_ns: u64, which: Icmp6Mib) {
    counters(net_ns).icmp[which.index()].fetch_add(1, Ordering::Relaxed);
}
/// Read one ICMPv6 MIB event. # C: O(log N namespaces)
pub fn get_icmp(net_ns: u64, which: Icmp6Mib) -> u64 {
    counters(net_ns).icmp[which.index()].load(Ordering::Relaxed)
}
/// Count one UDPv6 MIB event. # C: O(log N namespaces)
pub fn bump_udp(net_ns: u64, which: Udp6Mib) {
    counters(net_ns).udp[which.index()].fetch_add(1, Ordering::Relaxed);
}
/// Read one UDPv6 MIB event. # C: O(log N namespaces)
pub fn get_udp(net_ns: u64, which: Udp6Mib) -> u64 {
    counters(net_ns).udp[which.index()].load(Ordering::Relaxed)
}
/// Count one ICMPv6 type event; `outbound` selects the output half. # C: O(log N namespaces)
pub fn bump_icmp_type(net_ns: u64, outbound: bool, typ: u8) {
    let index = typ as usize + if outbound { 256 } else { 0 };
    counters(net_ns).icmp_type[index].fetch_add(1, Ordering::Relaxed);
}
/// Read one ICMPv6 type event. # C: O(log N namespaces)
pub fn get_icmp_type(net_ns: u64, outbound: bool, typ: u8) -> u64 {
    let index = typ as usize + if outbound { 256 } else { 0 };
    counters(net_ns).icmp_type[index].load(Ordering::Relaxed)
}

/// Account one packet entering IPv6 output after its final wire shape exists. # C: O(log N namespaces)
pub fn account_output(net_ns: u64, dst: crate::Ipv6Addr, bytes: usize) {
    bump_ip(net_ns, Ip6Mib::OutTransmits);
    add_ip(net_ns, Ip6Mib::OutOctets, bytes as u64);
    if dst.is_multicast() {
        bump_ip(net_ns, Ip6Mib::OutMcastPkts);
        add_ip(net_ns, Ip6Mib::OutMcastOctets, bytes as u64);
    }
}

/// Discard all dynamic MIB state owned by a removed namespace. # C: O(log N namespaces)
pub fn forget(net_ns: u64) { if net_ns != INITIAL_NET_NS { NAMESPACES.lock().remove(&net_ns); } }

const IP_ROWS: [(&str, Ip6Mib); IP6_COUNTERS] = [
    ("Ip6InReceives", Ip6Mib::InReceives), ("Ip6InHdrErrors", Ip6Mib::InHdrErrors),
    ("Ip6InTooBigErrors", Ip6Mib::InTooBigErrors), ("Ip6InNoRoutes", Ip6Mib::InNoRoutes),
    ("Ip6InAddrErrors", Ip6Mib::InAddrErrors), ("Ip6InUnknownProtos", Ip6Mib::InUnknownProtos),
    ("Ip6InTruncatedPkts", Ip6Mib::InTruncatedPkts), ("Ip6InDiscards", Ip6Mib::InDiscards),
    ("Ip6InDelivers", Ip6Mib::InDelivers), ("Ip6OutForwDatagrams", Ip6Mib::OutForwDatagrams),
    ("Ip6OutRequests", Ip6Mib::OutRequests), ("Ip6OutDiscards", Ip6Mib::OutDiscards),
    ("Ip6OutNoRoutes", Ip6Mib::OutNoRoutes), ("Ip6ReasmTimeout", Ip6Mib::ReasmTimeout),
    ("Ip6ReasmReqds", Ip6Mib::ReasmReqds), ("Ip6ReasmOKs", Ip6Mib::ReasmOks),
    ("Ip6ReasmFails", Ip6Mib::ReasmFails), ("Ip6FragOKs", Ip6Mib::FragOks),
    ("Ip6FragFails", Ip6Mib::FragFails), ("Ip6FragCreates", Ip6Mib::FragCreates),
    ("Ip6InMcastPkts", Ip6Mib::InMcastPkts), ("Ip6OutMcastPkts", Ip6Mib::OutMcastPkts),
    ("Ip6InOctets", Ip6Mib::InOctets), ("Ip6OutOctets", Ip6Mib::OutOctets),
    ("Ip6InMcastOctets", Ip6Mib::InMcastOctets), ("Ip6OutMcastOctets", Ip6Mib::OutMcastOctets),
    ("Ip6InBcastOctets", Ip6Mib::InBcastOctets), ("Ip6OutBcastOctets", Ip6Mib::OutBcastOctets),
    ("Ip6InNoECTPkts", Ip6Mib::InNoEctPkts), ("Ip6InECT1Pkts", Ip6Mib::InEct1Pkts),
    ("Ip6InECT0Pkts", Ip6Mib::InEct0Pkts), ("Ip6InCEPkts", Ip6Mib::InCePkts),
    ("Ip6OutTransmits", Ip6Mib::OutTransmits),
];
const ICMP_ROWS: [(&str, Icmp6Mib); ICMP6_COUNTERS] = [
    ("Icmp6InMsgs", Icmp6Mib::InMsgs), ("Icmp6InErrors", Icmp6Mib::InErrors),
    ("Icmp6OutMsgs", Icmp6Mib::OutMsgs), ("Icmp6OutErrors", Icmp6Mib::OutErrors),
    ("Icmp6InCsumErrors", Icmp6Mib::InCsumErrors), ("Icmp6OutRateLimitHost", Icmp6Mib::OutRateLimitHost),
];
const UDP_ROWS: [(&str, Udp6Mib); UDP6_COUNTERS] = [
    ("Udp6InDatagrams", Udp6Mib::InDatagrams), ("Udp6NoPorts", Udp6Mib::NoPorts),
    ("Udp6InErrors", Udp6Mib::InErrors), ("Udp6OutDatagrams", Udp6Mib::OutDatagrams),
    ("Udp6RcvbufErrors", Udp6Mib::RcvbufErrors), ("Udp6SndbufErrors", Udp6Mib::SndbufErrors),
    ("Udp6InCsumErrors", Udp6Mib::InCsumErrors), ("Udp6IgnoredMulti", Udp6Mib::IgnoredMulti),
    ("Udp6MemErrors", Udp6Mib::MemErrors),
];
const ICMP_TYPE_NAMES: [(u8, &str); 15] = [
    (1, "DestUnreachs"), (2, "PktTooBigs"), (3, "TimeExcds"), (4, "ParmProblems"),
    (128, "Echos"), (129, "EchoReplies"), (130, "GroupMembQueries"),
    (131, "GroupMembResponses"), (132, "GroupMembReductions"), (143, "MLDv2Reports"),
    (134, "RouterAdvertisements"), (133, "RouterSolicits"), (136, "NeighborAdvertisements"),
    (135, "NeighborSolicits"), (137, "Redirects"),
];

/// Render `/proc/net/snmp6` for one network namespace. # C: O(IPv6 counters)
pub fn render_proc_snmp6(net_ns: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut out = alloc::string::String::new();
    for (name, which) in IP_ROWS { let _ = writeln!(out, "{name:<32}\t{}", get_ip(net_ns, which)); }
    for (name, which) in ICMP_ROWS { let _ = writeln!(out, "{name:<32}\t{}", get_icmp(net_ns, which)); }
    for (typ, name) in ICMP_TYPE_NAMES {
        let _ = writeln!(out, "Icmp6In{name:<25}\t{}", get_icmp_type(net_ns, false, typ));
        let _ = writeln!(out, "Icmp6Out{name:<24}\t{}", get_icmp_type(net_ns, true, typ));
    }
    for typ in 0..=u8::MAX {
        for outbound in [false, true] {
            let value = get_icmp_type(net_ns, outbound, typ);
            if value != 0 && !ICMP_TYPE_NAMES.iter().any(|(known, _)| *known == typ) {
                let direction = if outbound { "Out" } else { "In" };
                let _ = writeln!(out, "Icmp6{direction}Type{typ:<20}\t{value}");
            }
        }
    }
    for (name, which) in UDP_ROWS { let _ = writeln!(out, "{name:<32}\t{}", get_udp(net_ns, which)); }
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    const NS: u64 = 0x638;
    #[test]
    fn render_is_namespace_scoped_and_includes_protocol_type_rows() {
        forget(NS); forget(NS + 1);
        bump_ip(NS, Ip6Mib::InReceives); bump_icmp(NS, Icmp6Mib::InMsgs);
        bump_icmp_type(NS, false, 128); bump_udp(NS, Udp6Mib::InDatagrams);
        let body = alloc::string::String::from_utf8(render_proc_snmp6(NS)).unwrap();
        assert!(body.lines().any(|line| line.starts_with("Ip6InReceives") && line.ends_with("\t1")));
        assert!(body.lines().any(|line| line.starts_with("Icmp6InMsgs") && line.ends_with("\t1")));
        assert!(body.contains("Icmp6InEchos"));
        assert!(body.lines().any(|line| line.starts_with("Udp6InDatagrams") && line.ends_with("\t1")));
        assert!(alloc::string::String::from_utf8(render_proc_snmp6(NS + 1)).unwrap().lines()
            .any(|line| line.starts_with("Ip6InReceives") && line.ends_with("\t0")));
        forget(NS); forget(NS + 1);
    }

    #[test]
    fn ipv6_ingress_moves_only_the_namespace_owned_proc_counters() {
        let owner = crate::net_ns::test_support::allocate_namespace();
        let net_ns = owner.id().as_u64();
        forget(net_ns);
        let stack = crate::NetStack::new();
        let (iface, _) = stack.register_loopback_in(net_ns);
        let src = crate::Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
        let payload_len = crate::udp::UDP_HDR_LEN + 1;
        let mut packet = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN + payload_len];
        crate::ipv6::Ipv6Hdr::build(src, crate::Ipv6Addr::LOOPBACK,
            crate::IpProto::Udp, payload_len as u16)
            .write_to(&mut packet[..crate::ipv6::IPV6_HDR_LEN]);
        crate::udp::build_into_v6(40_000, 40_001, src, crate::Ipv6Addr::LOOPBACK, b"x",
            &mut packet[crate::ipv6::IPV6_HDR_LEN..]);
        stack.deliver_rx_ipv6(iface, &packet).unwrap();
        assert_eq!(get_ip(net_ns, Ip6Mib::InReceives), 1);
        assert_eq!(get_ip(net_ns, Ip6Mib::InOctets), packet.len() as u64);
        assert_eq!(get_ip(net_ns, Ip6Mib::InDelivers), 1);
        assert_eq!(get_udp(net_ns, Udp6Mib::NoPorts), 1);
        forget(net_ns);
    }

    #[test]
    fn ipv6_output_counts_the_final_wire_packet_in_its_socket_namespace() {
        let namespace = crate::net_ns::test_support::allocate_namespace();
        let net_ns = namespace.id().as_u64();
        forget(net_ns);
        let stack = crate::NetStack::new();
        let (iface, _) = stack.register_loopback_in(net_ns);
        let lease = stack.ifaces.acquire_egress_in_ns(iface, net_ns).unwrap();
        let owner = crate::SocketOwner::root(namespace, 81);
        let bytes = b"udp6";
        stack.xmit_ipv6_l4_with_policy(iface, lease, crate::Ipv6Addr::LOOPBACK,
            crate::Ipv6Addr::LOOPBACK, crate::Ipv6Addr::LOOPBACK, crate::IpProto::Udp, bytes,
            crate::ipv6::IPV6_DEFAULT_HOP_LIMIT, 0, 0, false, 0, usize::MAX, true,
            Some(&owner), &crate::send_control::Raw6Control::default(),
            crate::TxMeta::NONE).unwrap();
        assert_eq!(get_ip(net_ns, Ip6Mib::OutRequests), 1);
        assert_eq!(get_ip(net_ns, Ip6Mib::OutTransmits), 1);
        assert_eq!(get_ip(net_ns, Ip6Mib::OutOctets),
            (crate::ipv6::IPV6_HDR_LEN + bytes.len()) as u64);
        forget(net_ns);
    }
}
