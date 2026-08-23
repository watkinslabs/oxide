// NetStack: ifaces + routing + UDP/TCP demux. v6 helpers in
// stack_ipv6.rs. Hosted-testable via LoopbackDev.
//
// Module manifest:
// - types: queue/key/entry structs, timers, NetStack storage.
// - inet_tables: canonical per-network-namespace transport ownership.
// - pmtu_cache: expiring per-interface destination path-MTU exceptions.
// - core: constructor, iface, UDP, and listener setup helpers.
// - lifecycle: RTNL-serialized interface retire, destroy, and namespace return.
// - udp_endpoint: IPv4 UDP endpoint queue, errors, and close linearization.
// - udp_bind: IPv4 UDP bind admission and endpoint publication.
// - reuseport_join: bind-key SO_REUSEPORT group join against the bind tables.
// - tcp_bind: TCP local bind reservations and lifecycle transitions.
// - tcp_listener: TCP listener publication, accept, and passive-child teardown.
// - tcp: TCP active open, send/recv/close, retry, and demux.
// - tcp_timer: socket-owned write, delayed-ACK, keepalive, and cleanup timers.
// - tcp_open: public active-open and disconnect entry points.
// - tcp_tx: socket-owned TCP PMTU policy and family transmit dispatch.
// - tcp_metrics: the two moments a connection reads and writes the
//   per-destination metrics cache.
// - tcp_pmtu: validated TCP path-MTU reduction and immediate retransmit.
// - ipv4: IPv4 receive demux, loopback drain.
// - ipv4_nf_defrag: IPv4 fragment gathering before netfilter hook traversal.
// - ipv4_tx: IPv4 transmit and fragment accounting.
// - ipv4_route_tx: transmit-only IPv4 route outcome accounting.
// - rx_backlog: per-CPU receive backlog, poll list, and the NET_RX drain pass.
// - ethernet: canonical L2 ingress before bridge and L3 demultiplexing.
// - bridge: RTNL-owned port/FDB state and L2 forwarding decisions.
// - bridge_port_info: legacy bridge-port configuration snapshots.
// - bridge_config: legacy bridge timing configuration.
// - bridge_stp_bpdu: IEEE 802.1D configuration BPDU wire codec.
// - bridge_stp: canonical IEEE 802.1D root/port/timer state machine.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as StackLockClass};

use crate::addr::{IpAddr, IpProto, Ipv4Addr, Ipv6Addr, MacAddr, NetIfaceId};
use crate::icmp::{self, ICMP_TYPE_ECHO_REQUEST};
use crate::ipv4::{Ipv4Hdr, IPV4_HDR_LEN, push_ipv4_header};
use crate::loopback::LoopbackDev;
use crate::netdev::{IfaceRegistry, NetDev, NetError, NetResult};
use crate::pkt::Pkt;
use crate::route::RouteTable;
use crate::route6::Route6Table;
use crate::udp::UdpHdr;
use crate::tcp_hdr::{flags as tcp_flags, TCP_HDR_MIN_LEN};
use crate::tcp_conn::{TcpConn, Endpoint};

// Netfilter hook bridge lives in `netfilter_hook` (08§7 split). Re-export
// the public API so `net::stack::install_nf_hook` / `NF_INET_*` paths stay
// stable; pull the crate-internal helpers into scope for the packet path.
pub use crate::netfilter_hook::{NfHookCtx, NfHookFn, NfHookResult, install_nf_hook,
    install_nf_hook_with_stages, NFPROTO_IPV4,
    NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING};

/// Socket ownership selected by the live receive path for nftables socket
/// expressions. This is a snapshot so rule evaluation never retains an
/// endpoint lock.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SocketLookup {
    pub full: bool,
    pub transparent: bool,
    pub mark: u32,
    pub wildcard: bool,
}
use crate::netfilter_hook::nf_output;

pub use crate::bpf_filter::{
    install_bpf_filter_context_runner, install_bpf_filter_runner, install_bpf_reuseport_runner,
    BpfFilterContextFn, BpfFilterFn, BpfReuseportFn,
}; // bridge in bpf_filter.rs

/// The most of an opening handshake packet `TCP_SAVE_SYN` records: a maximal
/// network header plus a maximal TCP header with all its options.
pub const SAVED_SYN_MAX: usize = 60 + 60;

mod types;
mod inet_tables;
mod conntrack;
mod pmtu_cache;
pub(crate) use pmtu_cache::IPV4_MIN_PMTU;
mod core;
#[path = "stack_anycast.rs"]
pub(crate) mod anycast;
#[path = "stack_mcast_rtnl.rs"]
pub(crate) mod mcast_rtnl;
mod lifecycle;
mod udp_endpoint;
mod udp_bind;
mod reuseport_join;
mod tcp_bind;
pub(crate) mod tcp_listener;
pub use tcp_listener::TcpAcceptWait;
mod tcp;
mod tcp_timer;
mod tcp_fastopen;
mod tcp_listener_deliver;
mod tcp_syncookies;
#[cfg(test)]
#[path = "stack/tcp_syncookies_tests.rs"]
mod tcp_syncookies_tests;
#[cfg(test)]
#[path = "stack/tcp_accept_overflow_tests.rs"]
mod tcp_accept_overflow_tests;

#[cfg(test)]
#[path = "stack/tcp_metrics_tests.rs"]
mod tcp_metrics_tests;

#[cfg(test)]
#[path = "stack/tcp_save_syn_tests.rs"]
mod tcp_save_syn_tests;
mod tcp_reqsk;
#[cfg(test)]
#[path = "stack/tcp_req_tests.rs"]
mod tcp_req_tests;
// The slim half-open request record and the two-kind connection-table entry.
pub(crate) mod tcp_req;
pub(crate) use tcp_req::{TcpReq, TcpSlot};
mod tcp_metrics;
mod tcp_open;
pub(crate) mod tcp_writable;
pub(crate) mod tcp_rx_trace;
mod tcp_tx;
mod tcp_pmtu;
mod ipv4;
mod ipv4_nf_defrag;
#[cfg(test)]
mod ipv4_nf_defrag_tests;
mod ipv4_tx;
mod ipv4_route_tx;
mod rx_backlog;
mod ethernet;
mod neigh_rtnl;
mod bridge;
mod bridge_fdb;
mod bridge_info;
mod bridge_port_info;
mod bridge_config;
mod bridge_stp_bpdu;
mod bridge_stp;
mod stp_softirq;
mod bridge_dev;
mod bridge_tx;

pub use types::*;
pub use neigh_rtnl::{NeighAdminError, NeighV4};
pub use bridge_config::BridgeTiming;
pub use stp_softirq::{init as stp_softirq_init, raise_from_tick as stp_raise_from_tick};

impl NetStack {
    /// Look up the socket owning an IPv4 UDP packet in the ingress namespace.
    /// TCP, IPv6, and output-side ownership remain absent until their native
    /// demux tables provide the same packet-owner contract.
    pub fn socket_lookup_in(&self, net_ns: u64, family: u8, pkt: &[u8],
                            iface: Option<NetIfaceId>) -> Option<SocketLookup> {
        if family != NFPROTO_IPV4 || pkt.len() < 28 || pkt[0] >> 4 != 4
            || pkt[9] != IpProto::Udp as u8 { return None; }
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        if ihl < 20 || ihl + 8 > pkt.len() { return None; }
        let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
        let iface = iface?;
        self.udp_demux_in(net_ns, src, sport, dst, dport, iface, &[])
            .into_iter().next().map(|q| SocketLookup {
                full: true,
                transparent: q.transparent(),
                mark: q.mark(),
                wildcard: q.bound_ip.is_unspecified(),
            })
    }

    /// Test the transparent UDP target lookup used by nft_tproxy.
    pub fn transparent_udp4_in(&self, net_ns: u64, dst: Ipv4Addr, port: u16,
                               iface: Option<NetIfaceId>) -> bool {
        let tables = self.inet_tables(net_ns);
        let Some(group) = tables.udp.lock().get(&port).cloned() else { return false; };
        let ifindex = iface.map_or(0, NetIfaceId::raw);
        group.into_iter().any(|q| {
            let bound = q.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire);
            (bound == 0 || bound == ifindex)
                && (q.bound_ip.is_unspecified() || q.bound_ip == dst)
                && q.transparent()
        })
    }
}
