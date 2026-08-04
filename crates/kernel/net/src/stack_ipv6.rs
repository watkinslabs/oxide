// F180a: IPv6 transport methods on NetStack split by concern.
//
// Module manifest:
// - types.rs: IPv6 stack public-facing address/queue types.
// - control.rs: canonical IPv6 address/route events and expiry.
// - udp.rs:   IPv6 UDP bind/queue/send/recv operations.
// - rx.rs:    IPv6 receive path and protocol demux (ICMPv6/TCP/UDP/NDP).
// - tx.rs:    IPv6 L4 transmit helpers and fragmentation/MTU helpers.
// - ra.rs:    router-advertisement route and SLAAC transactions.
// - raw.rs:   raw IPv6 routing, extension headers, and fragmentation.
// - mld.rs:   MLD interface policy, reporting, and retry lifecycle.

mod types;
mod control;
mod udp;
mod rx;
mod rx_udp;
mod tx;
mod ra;
mod raw;
mod mld;
#[cfg(test)] mod ra_tests;
#[cfg(test)] mod dad_tests;

pub use types::{Ipv6AddrOrigin, Ipv6AddrState, Ipv6IfaceAddr, Udp6Datagram, Udp6RxQueue};
pub(crate) use types::PendingRa;
pub(crate) use tx::ipv6_output_mtu;
#[cfg(test)] pub(crate) use ra::DAD_DELAY_NS;
