use alloc::sync::Arc;

use super::{stack, InetSocket, RemoteAddr, SockKind};
use crate::{Ipv4Addr, NetError};

const RAW_MTU: u32 = 1_280;
const RAW_LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const RAW_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);

struct RawSinkDev;

impl crate::netdev::NetDev for RawSinkDev {
    fn name(&self) -> &str { "raw4err0" }
    fn mac(&self) -> crate::addr::MacAddr { crate::addr::MacAddr::ZERO }
    fn mtu(&self) -> u32 { RAW_MTU }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, _packet: crate::pkt::Pkt) -> crate::netdev::NetResult<()> { Ok(()) }
}

/// A raw IPv4 socket in its own namespace, routed over one `RAW_MTU` link,
/// forbidden to fragment and collecting extended errors. # C: O(1)
fn raw4_socket() -> InetSocket {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let ns = owner.id().as_u64();
    let iface = stack().ifaces.register_in_ns(
        Arc::new(RawSinkDev) as Arc<dyn crate::netdev::NetDev>, ns);
    crate::iface_addr::set_primary_addr(ns, iface, RAW_LOCAL, 0);
    stack().routes.add_in(ns, crate::route::RouteEntry::main(
        RAW_DST, 32, iface, None, Some(RAW_LOCAL)));
    let sock = InetSocket::new_raw4_in(crate::addr::IpProto::Udp as u8, owner);
    sock.error.set_recverr4(true);
    sock.opts.ip_mtu_discover.store(crate::uapi::IP_PMTUDISC_DO,
        core::sync::atomic::Ordering::Release);
    sock
}

/// Enter the exact raw-IPv4 production owner selected by `sendto_inner`. # C: O(payload)
fn raw4_send(sock: &InetSocket, bytes: usize,
    control: &crate::send_control::SendControl) -> Result<usize, NetError>
{
    let endpoint = match &*sock.kind.lock() {
        SockKind::Raw4(endpoint) => endpoint.clone(),
        _ => unreachable!("the fixture builds a raw IPv4 socket"),
    };
    super::sendto_raw4(sock, &endpoint, &alloc::vec![0u8; bytes],
        Some(RemoteAddr::Inet { ip: RAW_DST, port: 0 }), control, crate::TxMeta::NONE)
}

// Linux's raw IPv4 send path calls ip_local_error before returning EMSGSIZE.
// Pin that pairing at the production boundary instead of testing the reporting
// helper in isolation.
#[test]
fn a_raw_ipv4_size_refusal_reports_the_local_error() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let sock = raw4_socket();

    assert_eq!(raw4_send(&sock, RAW_MTU as usize * 2,
        &crate::send_control::SendControl::default()), Err(NetError::Emsgsize));

    let entry = sock.error.take_extended().expect("the refusal queues a local record");
    assert_eq!(entry.origin, crate::socket_error::SO_EE_ORIGIN_LOCAL);
    assert_eq!(entry.errno, syscall::errno::Errno::Emsgsize as i32);
    assert_eq!(entry.destination, crate::addr::IpAddr::V4(RAW_DST));
    assert_eq!(entry.destination_port, 0);
    assert_eq!(entry.info, RAW_MTU);
}
