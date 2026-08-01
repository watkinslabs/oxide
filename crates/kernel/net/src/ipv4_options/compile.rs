// The namespace-aware entry to the option-area compile pass. One shape, one
// admission, for both `setsockopt(IP_OPTIONS)` and the `IP_OPTIONS` control
// message. No target gate.

use syscall::errno::Errno;

use crate::addr::Ipv4Addr;
use super::area::{self, AddrClass, Compiled};

/// The remote-unicast answer the timestamp option's prespecified form asks
/// for: an address this namespace does not own, and which is neither multicast
/// nor broadcast, belongs to another host, whose stamp slot is not ours.
pub struct RemoteUnicast {
    pub net_ns: u64,
}

impl AddrClass for RemoteUnicast {
    /// # C: O(addresses)
    fn is_unicast(&self, addr: [u8; 4]) -> bool {
        let addr = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
        if addr.is_multicast() || addr.is_broadcast() || addr.is_unspecified() { return false; }
        !crate::iface_addr::snapshot_ns(self.net_ns).iter().any(|row| row.addr == addr)
    }
}

/// Compile a caller-supplied option area against one namespace's own
/// addresses. # C: O(optlen + addresses)
pub fn build_in(bytes: &[u8], net_raw: bool, net_ns: u64) -> Result<Compiled, Errno> {
    area::build_with(bytes, net_raw, &RemoteUnicast { net_ns })
}

/// [`build_in`] for the transmit-side callers that speak the stack's error
/// type: a control message's option area is admitted exactly as the
/// socket-level option's is. # C: O(optlen + addresses)
pub fn build_control(bytes: &[u8], net_raw: bool, net_ns: u64)
    -> Result<Compiled, crate::netdev::NetError>
{
    build_in(bytes, net_raw, net_ns).map_err(|e| match e {
        Errno::Eperm => crate::netdev::NetError::Eperm,
        _ => crate::netdev::NetError::Einval,
    })
}
