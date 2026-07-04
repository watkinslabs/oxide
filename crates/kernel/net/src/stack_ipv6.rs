// F180a: IPv6 transport methods on NetStack split by concern.
//
// Module manifest:
// - types.rs: IPv6 stack public-facing address/queue types.
// - udp.rs:   IPv6 UDP bind/queue/send/recv operations.
// - rx.rs:    IPv6 receive path and protocol demux (ICMPv6/TCP/UDP/NDP).
// - tx.rs:    IPv6 L4 transmit helpers and fragmentation/MTU helpers.

mod types;
mod udp;
mod rx;
mod tx;

pub use types::{Ipv6IfaceAddr, Udp6RxQueue};
