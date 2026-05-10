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
pub mod icmpv6;
pub mod arp;
pub mod ethernet;
pub mod ndp;
pub mod udp;
pub mod tcp_hdr;
pub mod tcp_conn;
pub use tcp_conn::{TcpConn, TcpConnError, Endpoint};

pub mod unix_sock;
pub use unix_sock::{UnixDgram, UnixDgramQueue, UnixEnd, UnixListener, UnixPair, UnixRegistry};
pub mod route;
pub mod stack;
pub use stack::{NetStack, UdpRxQueue};
pub use route::{RouteEntry, RouteTable};
pub use ipv4::{Ipv4Hdr, Ipv4Error, push_ipv4_header, ip_checksum, IPV4_HDR_LEN};

pub use netdev::{NetDev, NetError, NetResult, IfaceRegistry, IfaceEntry, NetStats};

#[cfg(target_os = "oxide-kernel")]
pub mod sock;
pub use loopback::LoopbackDev;

pub use addr::{
    eth_p, IpAddr, IpProto, Ipv4Addr, Ipv6Addr, MacAddr, NetIfaceId, Port,
};
pub use pkt::{Pkt, PktError, KResult as PktKResult, DEFAULT_HEADROOM};
pub use tcp_state::{transition, TcpEvent, TcpState};

#[cfg(test)]
mod tests;

/// Subsystem-level error per `38`. Kept for the existing skeleton
/// `init` shim; per-module errors live in their own files.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotImplemented,
    NoMem,
    Inval,
    Io,
}

#[allow(dead_code)]
pub(crate) type StubResult<T> = core::result::Result<T, Error>;

/// Initialization entry; called by the kernel boot phase per `00§3` /
/// `boot-flow.md`. v1 returns `NotImplemented`; bodies in P1-N.
///
/// # SAFETY: caller is the boot path, runs single-CPU with IRQs off
/// per `boot-flow.md`. Subsystem-specific preconditions documented at
/// the implementation site.
///
/// # C: O(N_pfn) once at boot
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> StubResult<()> {
    Err(Error::NotImplemented)
}

#[cfg(test)]
mod stub_tests {
    use super::*;

    #[test]
    fn init_returns_not_implemented() {
        // SAFETY: hosted-test entry; nothing else has touched the subsystem; init's preconditions trivially hold.
        let r = unsafe { init() };
        assert_eq!(r, Err(Error::NotImplemented));
    }
}


#[cfg(target_os = "oxide-kernel")] pub mod unix_cmsg;
