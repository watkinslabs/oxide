// Per-family send admission: WHICH ancillary rule each family runs, and which
// destination and out-of-band answers it gives.
//
// Before this module the whole tree ran ONE rule — the SCM one — for every
// family that is not AF_UNIX. A UDP sender's `IP_PKTINFO` was therefore
// dropped on the floor while its `SCM_RIGHTS` was refused, which is the
// reference's answer inverted in both directions.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::*;
use super::common::{Phased, inet_file, netlink_file, rights_control, vsock_file};
use crate::control_family::admit;
use crate::test_support::unpoliced;

const SOL_SOCKET: i32 = 1;
const SOL_IP: i32 = 0;
const IP_TOS: i32 = 1;
const IP_TTL: i32 = 2;
const IP_PKTINFO: i32 = 8;
const SO_MARK: i32 = 36;

fn cmsg(level: i32, kind: i32, data: &[u8]) -> Vec<u8> {
    let len = 16 + data.len();
    let mut out = alloc::vec![0u8; (len + 7) & !7];
    out[..8].copy_from_slice(&(len as u64).to_ne_bytes());
    out[8..12].copy_from_slice(&level.to_ne_bytes());
    out[12..16].copy_from_slice(&kind.to_ne_bytes());
    out[16..16 + data.len()].copy_from_slice(data);
    out
}

fn task(pid: u32) -> sched::Task {
    sched::Task::new(pid, "send", sched::SchedClass::Normal { weight: 1024 })
}

#[test]
fn a_datagram_socket_takes_the_ip_level_controls_a_stream_ignores() {
    let _policy = unpoliced();
    let task = task(400);
    let ctx = SendContext::new(&task);
    let mut control = cmsg(SOL_IP, IP_TTL, &7i32.to_ne_bytes());
    control.extend_from_slice(&cmsg(SOL_IP, IP_TOS, &0x10i32.to_ne_bytes()));
    let mut pktinfo = [0u8; 12];
    pktinfo[..4].copy_from_slice(&3i32.to_ne_bytes());
    pktinfo[4..8].copy_from_slice(&[192, 0, 2, 9]);
    control.extend_from_slice(&cmsg(SOL_IP, IP_PKTINFO, &pktinfo));

    let udp = Arc::new(net::sock::InetSocket::new_udp());
    let settled = admit(&ctx, &udp, &control, None).unwrap();
    assert_eq!(settled.raw4.ttl, Some(7));
    assert_eq!(settled.raw4.tos, Some(0x10));
    assert_eq!(settled.raw4.source, Some(net::Ipv4Addr::new(192, 0, 2, 9)));
    assert_eq!(settled.raw4.iface, Some(net::NetIfaceId::from_raw(3)));

    // A stream runs only the generic rule, so the same buffer settles nothing
    // and objects to nothing.
    let tcp = Arc::new(net::sock::InetSocket::new_tcp());
    let settled = admit(&ctx, &tcp, &control, None).unwrap();
    assert_eq!(settled.raw4.ttl, None);
    assert_eq!(settled.raw4.tos, None);
}

#[test]
fn a_datagram_socket_refuses_an_unknown_type_at_its_own_level_only() {
    let _policy = unpoliced();
    let task = task(401);
    let ctx = SendContext::new(&task);
    let udp = Arc::new(net::sock::InetSocket::new_udp());
    assert_eq!(admit(&ctx, &udp, &cmsg(SOL_IP, 250, &[0; 4]), None), Err(Error::Einval));
    // A level this transport does not own is stepped over, not refused.
    assert!(admit(&ctx, &udp, &cmsg(41, 250, &[0; 4]), None).is_ok());
}

#[test]
fn descriptors_are_stepped_over_by_every_family_that_cannot_carry_them() {
    let _policy = unpoliced();
    let task = task(402);
    let ctx = SendContext::new(&task);
    let control = rights_control(&[0]);
    for socket in [net::sock::InetSocket::new_udp(), net::sock::InetSocket::new_tcp(),
        net::sock::InetSocket::new_packet(0, 3)]
    {
        assert!(admit(&ctx, &Arc::new(socket), &control, None).is_ok());
    }
    // NETLINK is the family that runs the SCM rule WITHOUT descriptors, and it
    // keeps its refusal.
    let mut io = Phased { target: netlink_file(), events: Vec::new(), name: None };
    let _ = &mut io;
    let message = Message { requested_len: 1, control: control.clone(), ..Message::default() };
    assert_eq!(send(&ctx, netlink_file(), message, 0), Err(Error::Einval));
}

#[test]
fn the_generic_rule_gates_so_mark_on_a_capability_for_every_family_that_runs_it() {
    let _policy = unpoliced();
    let task = task(403);
    let ctx = SendContext::new(&task);
    task.creds.cap_effective.store(0, core::sync::atomic::Ordering::Release);
    task.creds.cap_permitted.store(0, core::sync::atomic::Ordering::Release);
    let control = cmsg(SOL_SOCKET, SO_MARK, &1u32.to_ne_bytes());
    for socket in [net::sock::InetSocket::new_udp(), net::sock::InetSocket::new_tcp()] {
        assert_eq!(admit(&ctx, &Arc::new(socket), &control, None), Err(Error::Eperm));
    }
    // The same message from a capable caller is admitted, so the refusal above
    // is the capability answer and not a length or type one.
    task.creds.cap_effective.store(u64::MAX, core::sync::atomic::Ordering::Release);
    assert!(admit(&ctx, &Arc::new(net::sock::InetSocket::new_udp()), &control, None).is_ok());
}

#[test]
fn an_ipv6_socket_runs_the_ipv6_rule_and_its_v4_mapped_fallback_runs_the_ipv4_one() {
    let _policy = unpoliced();
    let task = task(404);
    let ctx = SendContext::new(&task);
    let udp6 = Arc::new(net::sock::InetSocket::new_udp6());
    // `IP_TTL` is not the IPv6 transport's level, so it is stepped over.
    assert!(admit(&ctx, &udp6, &cmsg(SOL_IP, IP_TTL, &7i32.to_ne_bytes()), None).is_ok());
    // A v4-mapped destination hands the message to the IPv4 sender, and the
    // IPv4 rule then answers the same buffer.
    let mut mapped = [0u8; 16];
    mapped[10] = 0xff; mapped[11] = 0xff; mapped[12..].copy_from_slice(&[10, 0, 0, 1]);
    let address = crate::address::InetAddress::V6 { ip: net::Ipv6Addr(mapped), port: 53,
        scope_id: 0, flowinfo: 0 };
    let settled = admit(&ctx, &udp6, &cmsg(SOL_IP, IP_TTL, &7i32.to_ne_bytes()),
        Some(&address)).unwrap();
    assert_eq!(settled.raw4.ttl, Some(7));
}

#[test]
fn an_out_of_band_datagram_send_is_refused_on_the_ipv4_path() {
    let _policy = unpoliced();
    let task = task(405);
    let ctx = SendContext::new(&task);
    let target = inet_file(Arc::new(net::sock::InetSocket::new_udp()));
    let mut io = Phased { target, events: Vec::new(), name: None };
    assert_eq!(send_io(&ctx, net::uapi::MSG_OOB as u32, &mut io), Err(Error::Eopnotsupp));
    // The refusal precedes the destination, so no payload was ever imported.
    assert_eq!(io.events, ["file", "envelope"]);
}

#[test]
fn a_unix_byte_stream_refuses_a_destination_and_names_its_connection_state() {
    let _policy = unpoliced();
    let task = task(406);
    let ctx = SendContext::new(&task);
    let name = Some(alloc::vec![1u8, 0, b'/', b'x', 0]);

    let unbound = inet_file(Arc::new(net::sock::InetSocket::new_unix()));
    assert_eq!(send(&ctx, unbound.clone(), Message { requested_len: 1, name: name.clone(),
        ..Message::default() }, 0), Err(Error::Eopnotsupp));
    // With no destination the same socket reports the connection it never made.
    assert_eq!(send(&ctx, unbound, Message { requested_len: 1, ..Message::default() }, 0),
        Err(Error::Enotconn));

    let pair = net::UnixPair::new();
    let connected = inet_file(Arc::new(net::sock::InetSocket::new_unix_pair_end_in(
        network_namespace::initial(), pair, net::UnixEnd::A)));
    assert_eq!(send(&ctx, connected, Message { requested_len: 1, name,
        ..Message::default() }, 0), Err(Error::Eisconn));
}

#[test]
fn an_unconnected_unix_datagram_send_reports_the_missing_connection() {
    let _policy = unpoliced();
    let task = task(407);
    let ctx = SendContext::new(&task);
    let target = inet_file(Arc::new(net::sock::InetSocket::new_unix_dgram()));
    assert_eq!(send(&ctx, target, Message { requested_len: 1, ..Message::default() }, 0),
        Err(Error::Enotconn));
}

#[test]
fn a_vsock_destination_is_judged_by_state_not_by_the_socket_variant() {
    let _policy = unpoliced();
    let task = task(408);
    let ctx = SendContext::new(&task);
    let owner = net::vsock::VsockOwner::from_raw(0x0c00_0043).unwrap();
    for (state, expected) in [(net::vsock::VsockState::Connected, Error::Eisconn),
        (net::vsock::VsockState::Connecting, Error::Eopnotsupp),
        (net::vsock::VsockState::Closed, Error::Eopnotsupp)]
    {
        let conn = Arc::new(net::vsock::VsockConn::new(owner, 3, 62_101, 2, 1024, state));
        let socket = Arc::new(net::vsock_socket::VsockSocket::new());
        *socket.kind.lock() = net::vsock_socket::VsockKind::Conn(conn);
        assert_eq!(send(&ctx, vsock_file(socket), Message { name: Some(alloc::vec![0; 16]),
            ..Message::default() }, 0), Err(expected));
    }
}
