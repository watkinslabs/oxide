// NetStack core manifest: construction/locks, conntrack control, route metrics,
// IPv6 address/neighbour state, loopback registration, and transport helpers.
#[path = "core/init.rs"]
mod init;
#[path = "core/conntrack.rs"]
mod conntrack;
#[path = "core/routing.rs"]
mod routing;
#[path = "core/ipv6.rs"]
mod ipv6;
#[path = "core/loopback.rs"]
mod loopback;
#[path = "core/transport.rs"]
mod transport;
