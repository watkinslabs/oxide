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

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod addr;
pub mod pkt;
pub mod tcp_state;
pub mod netdev;
pub mod sysctl;
pub mod uapi;
pub mod send_control;
pub mod socket_args;
pub mod socket_error;
pub mod ephemeral;
pub use socket_error::{SocketError, SocketErrorEntry};
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
pub mod tcp_hdr;
pub mod tcp_conn;
pub use tcp_conn::{TcpConn, TcpConnError, Endpoint};

pub mod unix_sock;
pub use unix_sock::{
    GcPin, GcRights, GcTransferGuard, UnixAddr, UnixAddrKey, UnixConnectError, UnixDgram, UnixDgramQueue, UnixEnd, UnixListener, UnixMsgError, UnixMsgKind, UnixMsgPair, UnixPair, UnixRegistry, UnixStreamError,
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
pub mod route6;
pub mod policy_rule;
pub mod forwarding;
pub mod iface_addr;
pub mod netfilter_hook;
pub mod bpf_filter;
pub mod mcast_filter;
pub mod raw4;
pub mod raw6;
mod mcast_state;
pub mod stack;
pub mod stack_binddev;
pub mod stack_forward;
pub mod stack_diag;
mod global;
pub use global::global_stack;
pub use stack::{BridgeTiming, NetStack, UdpRxQueue};
pub use route::{RouteEntry, RouteRecord, RouteTable};
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
#[cfg(target_os = "oxide-kernel")]
pub mod sock_io;
#[cfg(target_os = "oxide-kernel")]
pub mod sock_recv;
#[cfg(target_os = "oxide-kernel")]
pub(crate) mod sock_vfs_read;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub mod sock_drop;
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
mod tests_socket_filter;
#[cfg(test)]
mod tests_ipv6_local;
#[cfg(test)]
mod tests_ipv4_udp_errors;
#[cfg(test)]
mod tests_inet_netns;

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

/// B288 diagnostic: dump AF_UNIX SOCK_DGRAM payloads sent to the
/// journal / syslog / sd_notify sockets so early-boot service error
/// strings (tmpfiles/sysusers/udevd/journald) surface in klog. The
/// services log their fatal reason to journald's socket (which queues
/// because journald itself is wedged), so the payload is the only
/// place the human-readable cause appears. Gated on `debug-boot`.
/// # C: O(payload bytes)
#[cfg(all(target_os = "oxide-kernel", feature = "debug-boot"))]
pub fn trace_dgram_journal(path: &[u8], payload: &[u8]) {
    let is_journal = path.windows(7).any(|w| w == b"journal")
        || path.windows(4).any(|w| w == b"/log")
        || path.windows(6).any(|w| w == b"notify")
        || path.windows(7).any(|w| w == b"dev-log");
    if !is_journal { return; }
    klog::write_raw(b"[B288 dgram ");
    klog::write_raw(&crate::unix_sock::unix_path_display(path));
    klog::write_raw(b" pid=");
    let pid = sched::live::current().map(|t| t.tgid.load(core::sync::atomic::Ordering::Acquire)).unwrap_or(0);
    klog::write_dec_u64(pid as u64);
    klog::write_raw(b"] ");
    // Cap the dump so a huge journal record can't flood the UART.
    let n = core::cmp::min(payload.len(), 512);
    klog::write_raw(&payload[..n]);
    klog::write_raw(b"\n");
}

/// No-op when debug-boot is off.
/// # C: O(1)
#[cfg(not(all(target_os = "oxide-kernel", feature = "debug-boot")))]
#[inline]
pub fn trace_dgram_journal(_path: &[u8], _payload: &[u8]) {}

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
