// `ipv6_iface_scope_id` behaviour: only interface- and link-scoped addresses
// carry a device, and the socket-level SO_BINDTODEVICE setting outranks the
// endpoint binding when both exist.

use super::{name_bound_ifindex, name_scope_id};
use crate::sock::InetSocket;
use core::sync::atomic::Ordering;

fn addr(bytes: [u8; 16]) -> crate::Ipv6Addr { crate::Ipv6Addr(bytes) }

#[test]
fn link_local_unicast_reports_the_device() {
    let link_local = addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(name_scope_id(link_local, 9), 9);
}

#[test]
fn global_unicast_reports_no_device() {
    let global = addr([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(name_scope_id(global, 9), 0, "a global address is never scoped");
    let loopback = addr([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(name_scope_id(loopback, 9), 0);
}

#[test]
fn multicast_scope_boundary_is_link_local() {
    // ff02:: — link-local multicast carries the device.
    assert_eq!(name_scope_id(addr([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), 4), 4);
    // ff01:: — interface-local, also scoped.
    assert_eq!(name_scope_id(addr([0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), 4), 4);
    // ff05:: — site-local multicast is above the boundary and carries none.
    assert_eq!(name_scope_id(addr([0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), 4), 0);
    // ff0e:: — global multicast.
    assert_eq!(name_scope_id(addr([0xff, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), 4), 0);
}

#[test]
fn socket_level_binding_outranks_the_absent_endpoint() {
    let sock = InetSocket::new_udp6();
    assert_eq!(name_bound_ifindex(&sock), 0, "an unbound socket names no device");
    sock.opts.base.bound_ifindex.store(11, Ordering::Release);
    assert_eq!(name_bound_ifindex(&sock), 11);
}
