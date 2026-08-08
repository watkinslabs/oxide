// IPv4 route failure statistics must belong to sends, not route inspection.

use crate::{Ipv4Addr, NetError};
use crate::stack::NetStack;

const NS: u64 = 0x4d49_425f_4f55_54;
const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

#[test]
fn only_a_transmit_route_failure_moves_out_no_routes() {
    crate::mib::forget(NS);
    let stack = NetStack::new();
    assert_eq!(crate::mib::get(NS, crate::mib::Mib::IpOutNoRoutes), 0);
    assert!(matches!(stack.route_v4_iface_in(NS, DST, None, 0), Err(NetError::Enetunreach)));
    assert_eq!(crate::mib::get(NS, crate::mib::Mib::IpOutNoRoutes), 0);
    assert!(matches!(stack.route_v4_xmit_in(NS, DST, None, 0), Err(NetError::Enetunreach)));
    assert_eq!(crate::mib::get(NS, crate::mib::Mib::IpOutNoRoutes), 1);
    crate::mib::forget(NS);
}
