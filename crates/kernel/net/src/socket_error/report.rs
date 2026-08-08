//! Local-origin reporting for transmit failures the host itself detects.

use crate::addr::IpAddr;
use crate::NetIfaceId;
use crate::NetError;

use super::queue::SocketError;

/// Report the local-origin extended error a failed transmit produces, and hand
/// the failure back unchanged.
///
/// A size failure is the one transmit outcome the host can describe: it
/// records the destination that could not be reached and the path MTU that
/// rejected the datagram. The failing send still returns its errno, so this
/// never publishes a pending errno of its own. # C: O(route lookup)
pub fn report_send_failure(error: &SocketError, net_ns: u64, dst: IpAddr, port: u16,
    iface: Option<NetIfaceId>, failure: NetError) -> NetError
{
    report_send_failure_pmtu(error, net_ns, dst, port, iface, failure, false)
}

/// The same report for an IPv6 sender, which has a SECOND way to learn the
/// rejecting MTU: `IPV6_RECVPATHMTU` collects a bare announcement from an
/// ordinary receive rather than from the error queue. Both are published from
/// this one point, so a socket with both switched on cannot be told two
/// different numbers, and a socket with neither is charged for nothing.
/// # C: O(route lookup)
pub fn report_send_failure_pmtu(error: &SocketError, net_ns: u64, dst: IpAddr, port: u16,
    iface: Option<NetIfaceId>, failure: NetError, recvpathmtu: bool) -> NetError
{
    if failure != NetError::Emsgsize { return failure; }
    let mtu = crate::global_stack().path_mtu_in(net_ns, dst, iface, false).unwrap_or(0);
    error.publish_local(syscall::errno::Errno::Emsgsize as i32, dst, port, mtu);
    if let (true, IpAddr::V6(ip)) = (recvpathmtu, dst) {
        error.pathmtu.publish(super::pathmtu::PathMtuReport {
            dst: ip, oif: iface.map_or(0, |id| id.0), mtu });
    }
    failure
}
