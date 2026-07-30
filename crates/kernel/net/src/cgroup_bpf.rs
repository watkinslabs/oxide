//! Cgroup BPF context translation for socket-owned network paths.

use alloc::vec::Vec;

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
use crate::sock::{InetSocket, SockKind};

/// Mutable Linux `bpf_sock_addr` address fields in raw network byte order.
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub struct SockAddr {
    pub user_family: u32,
    pub user_ip4: u32,
    pub user_ip6: [u32; 4],
    pub user_port: u32,
}

/// Socket-address cgroup hook selected after kernel sockaddr copy.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub enum SockAddrOp { Bind4, Bind6, Connect4, Connect6 }

/// Select a bind hook from the socket family, independent of `sa_family`. # C: O(1)
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn bind_op(socket_family: u16, _user_family: u16) -> Option<SockAddrOp> {
    match socket_family {
        crate::sock::AF_INET => Some(SockAddrOp::Bind4),
        crate::sock::AF_INET6 => Some(SockAddrOp::Bind6),
        _ => None,
    }
}

/// Select the socket-family connect hook before protocol family validation. # C: O(1)
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn connect_op(socket_family: u16, user_family: u16,
                  transport: Option<(u32, u32)>, ipv6_v6only: bool)
    -> crate::netdev::NetResult<Option<SockAddrOp>>
{
    if user_family == crate::socket_args::AF_UNSPEC as u16 { return Ok(None); }
    let Some((_, protocol)) = transport else { return Ok(None); };
    let op = match socket_family {
        crate::sock::AF_INET => SockAddrOp::Connect4,
        crate::sock::AF_INET6
            if protocol == crate::addr::IpProto::Udp as u32
                && user_family == crate::sock::AF_INET =>
        {
            if ipv6_v6only { return Err(crate::netdev::NetError::Eafnosupport); }
            SockAddrOp::Connect4
        }
        crate::sock::AF_INET6 => SockAddrOp::Connect6,
        _ => return Ok(None),
    };
    Ok(Some(op))
}

/// Validate the original protocol family after a selected connect hook ran. # C: O(1)
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn validate_connect_family(socket_family: u16, user_family: u16,
                               transport: Option<(u32, u32)>, ipv6_v6only: bool)
    -> crate::netdev::NetResult<()>
{
    let udp = transport.is_some_and(|(_, protocol)| {
        protocol == crate::addr::IpProto::Udp as u32
    });
    match (socket_family, user_family) {
        (crate::sock::AF_INET, crate::sock::AF_INET)
        | (crate::sock::AF_INET6, crate::sock::AF_INET6) => Ok(()),
        (crate::sock::AF_INET6, crate::sock::AF_INET) if udp && !ipv6_v6only => Ok(()),
        _ => Err(crate::netdev::NetError::Eafnosupport),
    }
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn run_sock_addr_transport(sock: &InetSocket, transport: Option<(u32, u32)>,
                           op: SockAddrOp, addr: &mut SockAddr)
    -> Result<bool, i32>
{
    let Some((socket_type, protocol)) = transport else { return Ok(false); };
    let attach = match op {
        SockAddrOp::Bind4 => security::bpf::CgroupSockAddrAttach::Inet4Bind,
        SockAddrOp::Bind6 => security::bpf::CgroupSockAddrAttach::Inet6Bind,
        SockAddrOp::Connect4 => security::bpf::CgroupSockAddrAttach::Inet4Connect,
        SockAddrOp::Connect6 => security::bpf::CgroupSockAddrAttach::Inet6Connect,
    };
    let mut context = security::bpf::CgroupSockAddrContext {
        user_family: addr.user_family,
        user_ip4: addr.user_ip4,
        user_ip6: addr.user_ip6,
        user_port: addr.user_port,
        family: sock.family.load(Ordering::Acquire) as u32,
        socket_type,
        protocol,
    };
    let verdict = security::bpf::run_cgroup_sock_addr(
        &sock.owner.cgroup, attach, &mut context,
    ).map_err(|error| error.as_i32())?;
    addr.user_ip4 = context.user_ip4;
    addr.user_ip6 = context.user_ip6;
    addr.user_port = context.user_port;
    Ok(verdict.bind_no_cap_net_bind_service)
}

/// Run one connect hook using lifecycle-preflight transport state. # C: O(programs)
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn run_sock_addr_preflight(sock: &InetSocket, transport: Option<(u32, u32)>,
                               op: SockAddrOp, addr: &mut SockAddr)
    -> Result<bool, i32>
{
    run_sock_addr_transport(sock, transport, op, addr)
}

/// Run one sockaddr hook and publish rewritten address fields only on success. # C: O(programs)
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn run_sock_addr(sock: &InetSocket, op: SockAddrOp, addr: &mut SockAddr)
    -> Result<bool, i32>
{
    run_sock_addr_transport(sock, transport(sock), op, addr)
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn transport(sock: &InetSocket) -> Option<(u32, u32)> {
    let socket_type = sock.opts.so_type.load(Ordering::Acquire) as u32;
    let protocol = match &*sock.kind.lock() {
        SockKind::Udp => crate::addr::IpProto::Udp as u32,
        SockKind::TcpInit | SockKind::TcpListener(_) | SockKind::TcpConn(_) =>
            crate::addr::IpProto::Tcp as u32,
        _ => return None,
    };
    Some((socket_type, protocol))
}

fn run_skb(owner: &crate::SocketOwner, attach: security::bpf::CgroupSkbAttach,
           packet: &[u8], ether_type: u16, ifindex: crate::NetIfaceId)
    -> Result<security::bpf::CgroupSkbVerdict, Errno> {
    let context = security::bpf::CgroupSkbContext {
        packet,
        protocol: ether_type.to_be() as u32,
        ifindex: ifindex.raw(),
    };
    security::bpf::run_cgroup_skb(&owner.cgroup, attach, context)
}

/// Run one socket-selected ingress hook over the complete L3 packet. # C: O(programs + packet)
pub(crate) fn ingress(owner: &crate::SocketOwner, packet: &[u8],
                      ether_type: u16, ifindex: crate::NetIfaceId) -> bool {
    run_skb(owner, security::bpf::CgroupSkbAttach::Ingress, packet, ether_type, ifindex)
        .is_ok_and(|verdict| verdict.allow)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum EgressVerdict { Allow, Congestion }

fn map_egress(verdict: security::bpf::CgroupSkbVerdict)
    -> crate::netdev::NetResult<EgressVerdict>
{
    if !verdict.allow { return Err(crate::netdev::NetError::Eperm); }
    Ok(if verdict.congestion_notification {
        EgressVerdict::Congestion
    } else {
        EgressVerdict::Allow
    })
}

/// Run one socket-owned egress hook after netfilter and before fragmentation. # C: O(programs + packet)
pub(crate) fn egress(owner: &crate::SocketOwner, packet: &[u8],
                     ether_type: u16, ifindex: crate::NetIfaceId)
    -> crate::netdev::NetResult<EgressVerdict>
{
    let verdict = run_skb(
        owner, security::bpf::CgroupSkbAttach::Egress, packet, ether_type, ifindex,
    ).map_err(|_| crate::netdev::NetError::Eperm)?;
    map_egress(verdict)
}

/// Rebuild the unfragmented IPv4 skb offered after transport reassembly. # C: O(packet)
pub(crate) fn reassembled_ipv4(header: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    if header.len() < crate::ipv4::IPV4_HDR_LEN { return None; }
    let total = header.len().checked_add(payload.len())?;
    if total > u16::MAX as usize { return None; }
    let mut packet = Vec::with_capacity(total);
    packet.extend_from_slice(header);
    packet.extend_from_slice(payload);
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    let old_flags = u16::from_be_bytes([packet[6], packet[7]]) & 0x4000;
    packet[6..8].copy_from_slice(&old_flags.to_be_bytes());
    packet[10..12].fill(0);
    let checksum = crate::ipv4::ip_checksum(&packet[..header.len()]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    Some(packet)
}

/// Copy the offset-zero packet's unfragmentable prefix without its Fragment header. # C: O(headers)
pub(crate) fn ipv6_fragment_prefix(original: &[u8], fragment_next_header: u8) -> Option<Vec<u8>> {
    if original.len() < crate::ipv6::IPV6_HDR_LEN { return None; }
    let mut next = original[6];
    let mut offset = crate::ipv6::IPV6_HDR_LEN;
    let mut next_field = 6usize;
    while matches!(next, crate::ipv6_ext::NH_HOP_BY_HOP
        | crate::ipv6_ext::NH_ROUTING | crate::ipv6_ext::NH_DEST_OPTS)
    {
        let header = original.get(offset..)?;
        let length = (header.get(1).copied()? as usize + 1) * 8;
        if length > header.len() { return None; }
        next_field = offset;
        next = header[0];
        offset += length;
    }
    if next != crate::ipv6_ext::NH_FRAGMENT || original.len() < offset + 8 { return None; }
    let mut prefix = original[..offset].to_vec();
    prefix[next_field] = fragment_next_header;
    Some(prefix)
}

/// Rebuild the unfragmented IPv6 skb from the offset-zero prefix. # C: O(packet)
pub(crate) fn reassembled_ipv6(prefix: &[u8], fragmentable: &[u8]) -> Option<Vec<u8>> {
    if prefix.len() < crate::ipv6::IPV6_HDR_LEN { return None; }
    let total = prefix.len().checked_add(fragmentable.len())?;
    let payload_len = total.checked_sub(crate::ipv6::IPV6_HDR_LEN)?;
    if payload_len > u16::MAX as usize { return None; }
    let mut packet = Vec::with_capacity(total);
    packet.extend_from_slice(prefix);
    packet.extend_from_slice(fragmentable);
    packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::{
        EgressVerdict, SockAddrOp, bind_op, connect_op, validate_connect_family,
    };

    #[test]
    fn unspec_runs_bind_hook_but_skips_connect_hook() {
        let unspec = crate::socket_args::AF_UNSPEC as u16;
        let udp = Some((crate::socket_args::SOCK_DGRAM, crate::addr::IpProto::Udp as u32));
        assert_eq!(bind_op(crate::sock::AF_INET, unspec), Some(SockAddrOp::Bind4));
        assert_eq!(bind_op(crate::sock::AF_INET6, unspec), Some(SockAddrOp::Bind6));
        assert_eq!(connect_op(crate::sock::AF_INET, unspec, udp, false), Ok(None));
        assert_eq!(connect_op(crate::sock::AF_INET6, unspec, udp, false), Ok(None));
    }

    #[test]
    fn dual_stack_udp_uses_connect4_and_v6only_rejects_before_hook() {
        let udp = Some((crate::socket_args::SOCK_DGRAM, crate::addr::IpProto::Udp as u32));
        let tcp = Some((crate::socket_args::SOCK_STREAM, crate::addr::IpProto::Tcp as u32));
        assert_eq!(
            connect_op(crate::sock::AF_INET6, crate::sock::AF_INET, udp, false),
            Ok(Some(SockAddrOp::Connect4)),
        );
        assert_eq!(
            connect_op(crate::sock::AF_INET6, crate::sock::AF_INET, udp, true),
            Err(crate::NetError::Eafnosupport),
        );
        assert_eq!(
            connect_op(crate::sock::AF_INET6, crate::sock::AF_INET, tcp, false),
            Ok(Some(SockAddrOp::Connect6)),
        );
    }

    #[test]
    fn incompatible_family_is_rejected_only_after_socket_family_hook() {
        let udp = Some((crate::socket_args::SOCK_DGRAM, crate::addr::IpProto::Udp as u32));
        let tcp = Some((crate::socket_args::SOCK_STREAM, crate::addr::IpProto::Tcp as u32));
        let garbage = 0x7fffu16;
        assert_eq!(
            connect_op(crate::sock::AF_INET, crate::sock::AF_INET6, tcp, false),
            Ok(Some(SockAddrOp::Connect4)),
        );
        assert_eq!(
            validate_connect_family(
                crate::sock::AF_INET, crate::sock::AF_INET6, tcp, false,
            ),
            Err(crate::NetError::Eafnosupport),
        );
        assert_eq!(
            connect_op(crate::sock::AF_INET, garbage, udp, false),
            Ok(Some(SockAddrOp::Connect4)),
        );
        assert_eq!(
            validate_connect_family(crate::sock::AF_INET, garbage, udp, false),
            Err(crate::NetError::Eafnosupport),
        );
        assert_eq!(
            connect_op(crate::sock::AF_INET6, garbage, udp, false),
            Ok(Some(SockAddrOp::Connect6)),
        );
        assert_eq!(
            validate_connect_family(crate::sock::AF_INET6, garbage, udp, false),
            Err(crate::NetError::Eafnosupport),
        );
        assert_eq!(
            connect_op(crate::sock::AF_INET6, crate::sock::AF_INET, tcp, false),
            Ok(Some(SockAddrOp::Connect6)),
        );
        assert_eq!(
            validate_connect_family(
                crate::sock::AF_INET6, crate::sock::AF_INET, tcp, false,
            ),
            Err(crate::NetError::Eafnosupport),
        );
    }

    #[test]
    fn ipv6_reassembly_preserves_headers_around_removed_fragment() {
        let mut original = alloc::vec![0u8; 56];
        original[0] = 0x60;
        original[4..6].copy_from_slice(&16u16.to_be_bytes());
        original[6] = crate::ipv6_ext::NH_DEST_OPTS;
        original[40] = crate::ipv6_ext::NH_FRAGMENT;
        original[41] = 0;
        original[48] = crate::addr::IpProto::Udp as u8;
        let fragmentable = [0x11u8; 8];
        let prefix = super::ipv6_fragment_prefix(
            &original, crate::addr::IpProto::Udp as u8,
        ).unwrap();
        let packet = super::reassembled_ipv6(&prefix, &fragmentable).unwrap();
        assert_eq!(packet.len(), 56);
        assert_eq!(packet[6], crate::ipv6_ext::NH_DEST_OPTS);
        assert_eq!(packet[40], crate::addr::IpProto::Udp as u8);
        assert_eq!(&packet[48..], &fragmentable);
    }

    #[test]
    fn egress_denial_is_eperm_and_congestion_remains_distinct() {
        let verdict = |allow, congestion_notification| security::bpf::CgroupSkbVerdict {
            allow, congestion_notification,
        };
        assert_eq!(super::map_egress(verdict(false, false)), Err(crate::NetError::Eperm));
        assert_eq!(super::map_egress(verdict(true, false)), Ok(EgressVerdict::Allow));
        assert_eq!(super::map_egress(verdict(true, true)), Ok(EgressVerdict::Congestion));
    }
}
