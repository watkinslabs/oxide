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
// - tcp_bind: TCP local bind reservations and lifecycle transitions.
// - tcp_listener: TCP listener publication, accept, and passive-child teardown.
// - tcp: TCP active open, send/recv/close, retry, and demux.
// - tcp_tx: socket-owned TCP PMTU policy and family transmit dispatch.
// - tcp_pmtu: validated TCP path-MTU reduction and immediate retransmit.
// - ipv4: IPv4 transmit, receive demux, loopback drain.
// - ethernet: canonical L2 ingress before bridge and L3 demultiplexing.
// - bridge: RTNL-owned port/FDB state and L2 forwarding decisions.

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
pub use crate::netfilter_hook::{NfHookFn, install_nf_hook, NFPROTO_IPV4,
    NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING};
use crate::netfilter_hook::{nf_hook_eval, nf_output};

pub use crate::bpf_filter::{
    install_bpf_filter_context_runner, install_bpf_filter_runner, BpfFilterContextFn, BpfFilterFn,
}; // bridge in bpf_filter.rs

mod types;
mod inet_tables;
mod pmtu_cache;
pub(crate) use pmtu_cache::IPV4_MIN_PMTU;
mod core;
mod lifecycle;
mod udp_endpoint;
mod tcp_bind;
pub(crate) mod tcp_listener;
pub use tcp_listener::TcpAcceptWait;
mod tcp;
mod tcp_tx;
mod tcp_pmtu;
mod ipv4;
mod ethernet;
mod bridge;
mod bridge_dev;

pub use types::*;
