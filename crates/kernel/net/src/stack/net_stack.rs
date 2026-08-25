use super::*;

pub struct NetStack {
    pub(crate) rtnl: crate::rtnl::Rtnl,
    pub ifaces: IfaceRegistry,
    pub routes: RouteTable,
    pub routes6: Route6Table,
    /// Canonical IPv4 proxy-neighbour keys, scoped to namespace and interface generation.
    pub(crate) arp_proxy: crate::arp::proxy::ProxyTable,
    /// Canonical bridge-port and forwarding database owner, serialized by RTNL.
    pub(crate) bridges: super::bridge::BridgeTable,
    /// Packets accepted by a bridge while its next-hop neighbour is unresolved.
    pub(crate) bridge_pending: Spinlock<BTreeMap<(NetIfaceId, IpAddr), BridgePending>, StackLockClass>,
    /// Sole AF_INET/AF_INET6 transport owner, indexed by network namespace.
    pub(crate) inet: super::inet_tables::InetTableLock<
        BTreeMap<u64, super::inet_tables::InetNamespaceTables>,
    >,
    /// One conntrack table per network namespace; packets carry the entry
    /// reference after the priority-ordered tracking hook attaches it.
    pub(crate) conntrack: Spinlock<BTreeMap<u64, Arc<::conntrack::CtNet>>, StackLockClass>,
    /// Namespace-owned software flowtables. Entries are installed only after
    /// conntrack confirmation and are consulted before the ordinary hook path.
    pub(crate) flow_offload: Spinlock<BTreeMap<(u64, String, String, ::conntrack::tuple::Tuple),
        Arc<super::flow_offload::FlowEntry>>, StackLockClass>,
    /// Configured nftables flowtable names, scoped by network namespace and family.
    pub(crate) flowtables: Spinlock<BTreeMap<(u64, u8, String, String), super::flow_offload::FlowtableConfig>, StackLockClass>,
    /// Unique nftables flowtable object handle source.
    pub(crate) next_flowtable_handle: crate::fib_lock::FibLock<u64, StackLockClass>,
    /// Monotonic id for IP packets we emit.
    pub(crate) next_ip_id: crate::fib_lock::FibLock<u16, StackLockClass>,
    /// Monotonic ISN base for TCP active opens.
    /// F180c: IPv6 neighbor cache keyed by ingress/egress interface.
    /// F195: IPv4 reassembly table.
    pub ipv4_reasm: crate::ipv4_reasm::ReasmTable,
    /// IPv6 Fragment extension reassembly table.
    pub ipv6_reasm: crate::ipv6_reasm::ReasmTable,
    /// F180c: per-iface IPv6 address registry (NS responder).
    pub(crate) v6_addrs: StackBhLock<BTreeMap<NetIfaceId, Vec<crate::stack_ipv6::Ipv6IfaceAddr>>>,
    /// IPv6 anycast address ownership, one ref for each socket membership.
    pub(crate) v6_anycast: StackBhLock<BTreeMap<NetIfaceId, Vec<super::anycast::AnycastAddr>>>,
    pub(crate) v6_mcast: StackBhLock<BTreeMap<NetIfaceId, Vec<crate::mcast_state::V6IfaceGroup>>>,
    pub(crate) v4_mcast: StackBhLock<BTreeMap<NetIfaceId, Vec<crate::mcast_state::V4IfaceGroup>>>,
    pub(crate) v6_ra_pending: StackBhLock<Vec<crate::stack_ipv6::PendingRa>>,
    /// Per-CPU receive backlog. Frames land here from a device's transmit-side
    /// caller and leave on the NET_RX bottom half's own stack, which is what
    /// keeps receive traversal off every transmit call chain.
    pub(crate) softnet: [crate::fib_lock::FibLock<super::rx_backlog::SoftnetData, StackLockClass>; cpu::MAX_CPUS],
    /// Receive sources the bottom half polls, registered at device creation.
    pub(crate) rx_poll: crate::fib_lock::FibLock<Vec<super::rx_backlog::RxPollEntry>, StackLockClass>,
    #[cfg(not(target_os = "oxide-kernel"))]
    pub(crate) ra_now_ns: ::core::sync::atomic::AtomicU64,
}

impl Default for NetStack { fn default() -> Self { Self::new() } }
