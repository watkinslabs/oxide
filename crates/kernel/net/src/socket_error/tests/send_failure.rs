//! The number a local-origin size refusal names.

use alloc::sync::Arc;

use crate::addr::{IpAddr, Ipv6Addr, MacAddr};
use crate::netdev::{NetDev, NetError, NetResult};
use crate::pkt::Pkt;
use crate::sock::stack;
use crate::socket_error::{report_send_failure_pmtu, SocketError};

const LINK_MTU: u32 = 1500;
const DST6: Ipv6Addr = Ipv6Addr([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
const HEADER_BYTES: u32 = 24;

struct SinkDev;

impl NetDev for SinkDev {
    fn name(&self) -> &str { "errq0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { LINK_MTU }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, _packet: Pkt) -> NetResult<()> { Ok(()) }
}

// The number a size refusal names is the room left for the PAYLOAD, so the
// header chain this send would have carried comes off the path MTU — and it
// comes off exactly once, so the queued record and the path-MTU announcement
// can never disagree.
#[test]
fn the_reported_path_mtu_excludes_the_headers_the_send_would_have_carried() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let ns = owner.id().as_u64();
    let iface = stack().ifaces.register_in_ns(Arc::new(SinkDev) as Arc<dyn NetDev>, ns);
    // The route lookup behind the report reads this namespace's transport
    // state, which its owner has to publish first.
    let _tables = stack().inet_tables_for(&owner);
    let dst = IpAddr::V6(DST6);

    let plain = SocketError::new();
    plain.set_recverr6(true);
    report_send_failure_pmtu(&plain, ns, dst, 53, Some(iface), NetError::Emsgsize, true, 0);
    let bare = plain.take_extended().expect("a local record").info;
    assert_eq!(bare, LINK_MTU, "no header chain leaves the path MTU alone");
    assert_eq!(plain.pathmtu.take().map(|note| note.mtu), Some(bare));

    let carried = SocketError::new();
    carried.set_recverr6(true);
    report_send_failure_pmtu(&carried, ns, dst, 53, Some(iface), NetError::Emsgsize, true,
        HEADER_BYTES);
    let queued = carried.take_extended().expect("a local record").info;
    assert_eq!(queued, bare - HEADER_BYTES, "the header bytes come off the announced MTU");
    assert_eq!(carried.pathmtu.take().map(|note| note.mtu), Some(queued),
        "both publishes name the same number");
}
