// Networking — IPv4/v6, TCP/UDP/ICMP, AF_UNIX/PACKET/etc.
//
// Foundation per docs/25:
//   addr.rs       — Mac/Ipv4/Ipv6/IpAddr/Port/IpProto/NetIfaceId/eth_p
//   pkt.rs        — `Pkt` packet buffer (push/pop/put/trim)
//   tcp_state.rs  — RFC 9293 11-state machine + transition table
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
pub mod loopback;
pub mod ipv4;
pub mod ipv6;
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
    UnixDgram, UnixDgramQueue, UnixEnd, UnixListener, UnixMsgPair, UnixPair, UnixRegistry,
    unix_path_display, unix_path_is_abstract,
};
pub mod route;
pub mod route6;
pub mod netfilter_hook;
pub mod bpf_filter;
pub mod stack;
pub mod stack_binddev;
pub mod stack_diag;
pub use stack::{NetStack, UdpRxQueue};
pub use route::{RouteEntry, RouteTable};
pub use route6::{Route6Entry, Route6Table};
pub use ipv4::{Ipv4Hdr, Ipv4Error, push_ipv4_header, ip_checksum, IPV4_HDR_LEN};

pub use netdev::{NetDev, NetError, NetResult, IfaceRegistry, IfaceEntry, NetStats, STAT_FIELDS};

#[cfg(target_os = "oxide-kernel")]
pub mod sock;
#[cfg(target_os = "oxide-kernel")]
pub mod sock_opts;
pub mod vsock;
pub mod vsock_socket;
#[cfg(target_os = "oxide-kernel")]
pub mod sock_io;
#[cfg(target_os = "oxide-kernel")]
pub mod sock_drop;
#[cfg(target_os = "oxide-kernel")]
pub mod sock_v6;
#[cfg(target_os = "oxide-kernel")]
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

// Real bring-up runs through the module functions (stack init in kmain,
// loopback/iface registration, the timer-driven TCP RTO below); there is
// no subsystem-level `init()` entrypoint. Per-module errors live in their
// own files (NetError, TcpConnError, PktError, ...).

#[cfg(target_os = "oxide-kernel")] pub mod unix_cmsg;

/// TCP retransmit / RTO + connection-abort timer for the timer driver.
/// Kernel-only: `sock`/`timer` are kernel modules; the host oracle
/// build (per `00§2` host-buildability) compiles the pure-protocol
/// modules + their tests without the socket/timer runtime.
/// # C: O(open connections)
#[cfg(target_os = "oxide-kernel")]
fn tcp_retx_timer(now_ns: u64) { sock::stack().tcp_retx_tick(now_ns); }

/// Register net's periodic timers (TCP retransmit). Boot, once.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn register_timers() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::AcqRel) { return; }
    timer::register_periodic(100_000_000, tcp_retx_timer);
}
