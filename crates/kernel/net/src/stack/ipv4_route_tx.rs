// IPv4 route resolution only for a datagram that is about to transmit.

use super::*;
use crate::ResolvedRoute;

impl NetStack {
    /// Resolve IPv4 egress for one actual transmit and count route failure.
    /// # C: O(N)
    pub(crate) fn route_v4_xmit_in(&self, net_ns: u64, dst: Ipv4Addr,
        bound: Option<NetIfaceId>, mark: u32)
        -> NetResult<(ResolvedRoute, crate::EgressLease, Ipv4Addr)>
    {
        match self.route_v4_iface_in(net_ns, dst, bound, mark) {
            Err(NetError::Enetunreach) => {
                crate::mib::bump(net_ns, crate::mib::Mib::IpOutNoRoutes);
                Err(NetError::Enetunreach)
            }
            result => result,
        }
    }
}
