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
    if failure != NetError::Emsgsize { return failure; }
    let mtu = crate::global_stack().path_mtu_in(net_ns, dst, iface, false).unwrap_or(0);
    error.publish_local(syscall::errno::Errno::Emsgsize as i32, dst, port, mtu);
    failure
}
