// Networking — IPv4/v6, TCP/UDP/ICMP, AF_UNIX/PACKET/etc.
//
// Foundation per docs/25:
//   addr.rs       — Mac/Ipv4/Ipv6/IpAddr/Port/IpProto/NetIfaceId/eth_p
//   pkt.rs        — `Pkt` packet buffer (push/pop/put/trim)
//   tcp_state.rs  — RFC 9293 11-state machine + transition table
//   uapi.rs       — socket message ABI flags
//
// Out of scope (follow-ups): NetDev trait + driver model, socket
// impl + RX/TX paths, routing, neighbor (ARP/NDP), netfilter,
// per-CPU `pkt_slab`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod addr;
pub mod ordered;
pub mod pkt;
pub mod tcp_state;
pub mod netdev;
pub mod sysctl;
pub mod uapi;
pub mod send_control;
pub mod landlock_glue;
pub mod socket_args;
// Receive ancillary messages: which control message each option produces, in
// what order, with what payload. Ungated so the whole decision is testable.
pub mod cmsg;
// The generalized hop-limit security check both IP levels expose.
pub mod min_hop;
pub mod sockaddr;
pub mod socket_error;
pub mod socket_owner;
pub mod cgroup_bpf;
pub mod ephemeral;
pub mod secure_seq;
pub use socket_error::{SocketError, SocketErrorEntry};
pub use socket_owner::SocketOwner;
pub use sockaddr::SockaddrStorage;
pub mod loopback;
pub mod ipv4;
pub mod ipv6;
pub mod ipv6_ext;
pub mod icmp;
pub mod igmp;
pub mod icmpv6;
pub mod arp;
pub mod ethernet;
pub mod ndp;
pub mod udp;
pub mod udp_gro;
#[cfg(test)]
mod udp_gro_endpoint_tests;
pub mod tcp_hdr;
pub mod tcp_conn;
pub use tcp_conn::{Endpoint, TcpCongestionControl, TcpConn, TcpConnError};

pub mod unix_sock;
pub use unix_sock::{
    GcPin, GcRights, GcTransferGuard, UnixAddr, UnixAddrKey, UnixConnectError, UnixDgram, UnixDgramQueue, PeerCred, UnixEnd, UnixListener, UnixMsgError, UnixMsgKind, UnixMsgPair, UnixPair, UnixRegistry, UnixStreamError,
    classify_files, transfer_guard,
    unix_path_display, unix_path_is_abstract,
};
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub use unix_sock::bind_file;
pub mod net_ns;
pub mod security_admission;
pub mod control_event;
#[cfg(any(test, feature = "hosted"))]
pub mod hosted_fixture;
mod rtnl;
pub use rtnl::RtnlGuard;
pub mod route;
pub mod route_metrics;
pub mod route6;
pub mod policy_rule;
pub mod forwarding;
pub mod iface_addr;
pub mod netfilter_hook;
pub mod bpf_filter;
pub mod reuseport;
pub mod mcast_filter;
pub mod raw4;
pub mod raw6;
pub mod ping;
mod mcast_state;
pub mod stack;
pub mod stack_binddev;
pub mod stack_forward;
pub mod stack_diag;
mod global;
pub use global::global_stack;
pub use stack::{BridgeTiming, NetStack, UdpRxQueue, stp_softirq_init, stp_raise_from_tick};
pub use route::{ResolvedRoute, RouteEntry, RouteRecord, RouteTable};
pub use route_metrics::RouteMetrics;
pub use route6::{Route6Entry, Route6Origin, Route6Table};
pub use ipv4::{Ipv4Hdr, Ipv4Error, push_ipv4_header, ip_checksum, IPV4_HDR_LEN};

pub use netdev::{
    EgressLease, IfaceEntry, IfaceMap, IfaceRegistry, IngressLease, NamespaceDropAction, NetDev, NetError, NetResult,
    WanSettings,
    NetStats, PACKET_LINK_ADDRESS_MAX, PacketChecksum, PacketLinkAddress, PacketRxMetadata,
    PacketVirtioMetadata,
    PacketRxMode, PacketVlan, STAT_FIELDS,
};

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub mod sock;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub mod sock_opts;
pub mod vsock;
pub mod vsock_socket;
#[cfg(any(target_os = "oxide-kernel", test))]
mod sock_error;
// Linux `sock_intr_errno` — NOT kernel-gated, so the ERESTARTSYS/EINTR rule
// every socket wait shares is unit-tested hosted.
pub mod sock_intr;
#[cfg(target_os = "oxide-kernel")]
pub mod sock_io;
#[cfg(target_os = "oxide-kernel")]
pub mod sock_recv;
#[cfg(target_os = "oxide-kernel")]
pub(crate) mod sock_vfs_read;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub mod sock_drop;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub mod sock_rtnl_defer;
#[cfg(target_os = "oxide-kernel")]
pub mod sock_v6;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub mod sock_mcast;
pub mod stack_ipv6;
pub mod stack_igmp;
pub mod tcp_cc;
pub mod stack_icmp;
pub mod ipv4_reasm;
pub mod ipv6_reasm;
pub use loopback::LoopbackDev;

pub use addr::{
    eth_p, IpAddr, IpProto, Ipv4Addr, Ipv6Addr, MacAddr, NetIfaceId, Port,
};
pub use pkt::{Pkt, PktError, KResult as PktKResult, DEFAULT_HEADROOM};
pub use tcp_state::{transition, TcpEvent, TcpState};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_correctness;
#[cfg(test)]
mod stack_tests;
#[cfg(test)]
mod stack_slaac_tests;
#[cfg(test)]
mod tests_udp_endpoint_groups;
#[cfg(test)]
mod tests_ipv6_udp_errors;
#[cfg(test)]
mod tests_ipv6_tclass;
#[cfg(test)]
mod tests_socket_filter;
#[cfg(test)]
mod tests_ipv6_local;
#[cfg(test)]
mod tests_ipv4_udp_errors;
#[cfg(test)]
mod tests_inet_netns;
#[cfg(test)]
mod tests_min_hop;
#[cfg(test)]
mod route_metrics_tests;

// Real bring-up runs through the module functions (stack init in kmain,
// loopback/iface registration, the timer-driven TCP RTO below); there is
// no subsystem-level `init()` entrypoint. Per-module errors live in their
// own files (NetError, TcpConnError, PktError, ...).


/// TCP retransmit / RTO + connection-abort timer for the timer driver.
/// Kernel-only: `sock`/`timer` are kernel modules; the host oracle
/// build (per `00§2` host-buildability) compiles the pure-protocol
/// modules + their tests without the socket/timer runtime.
/// # C: O(open connections)
#[cfg(target_os = "oxide-kernel")]
fn tcp_retx_timer(now_ns: u64) { sock::stack().tcp_retx_tick(now_ns); }

#[cfg(target_os = "oxide-kernel")]
fn mcast_retry_timer(now_ns: u64) { sock::stack().retry_multicast_reports(now_ns); }

#[cfg(target_os = "oxide-kernel")]
fn ipv6_control_timer(now_ns: u64) { sock::stack().ipv6_control_tick(now_ns); }
#[cfg(target_os = "oxide-kernel")]
fn arp_timer(now_ns: u64) { sock::stack().arp_tick(now_ns); }
#[cfg(target_os = "oxide-kernel")]
fn bridge_neighbour_timer(now_ns: u64) { sock::stack().bridge_neighbour_tick(now_ns); }
#[cfg(target_os = "oxide-kernel")]
fn packet_ring_timer(now_ns: u64) { sock::service_packet_ring_timers(now_ns); }

#[cfg(target_os = "oxide-kernel")]
const MCAST_RETRY_INTERVAL_NS: u64 = 100_000_000;

pub mod journal_trace;
pub use journal_trace::{message_field, trace_dgram_journal};


/// Register net's periodic timers. Boot, once.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn register_timers() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::AcqRel) { return; }
    timer::register_periodic(100_000_000, tcp_retx_timer);
    timer::register_periodic(MCAST_RETRY_INTERVAL_NS, mcast_retry_timer);
    timer::register_periodic(100_000_000, ipv6_control_timer);
    timer::register_periodic(100_000_000, arp_timer);
    timer::register_periodic(100_000_000, bridge_neighbour_timer);
    timer::register_periodic(1_000_000, packet_ring_timer);
}
