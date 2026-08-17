//! Shared fixture for the `AF_INET6` address-write tests: one registered
//! interface in the initial namespace, a request builder, and a table readback.
//!
//! Two sibling files use it — `address6_semantics` (what an add stores) and
//! `address6_ordering` (which errno wins, and what a delete matches).

use super::*;

pub(super) const LINK_LOCAL: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                              0xca, 0x67, 0xcf, 0xc6, 0xb1, 0x78, 0x90, 0x02];
pub(super) const GLOBAL: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11];

/// One `AF_INET6` address request. `attrs` are appended after `IFA_LOCAL`.
pub(super) fn addr6_req(ty: u16, ifindex: u32, prefixlen: u8, addr: [u8; 16], ifa_flags: u8, msg_flags: u16)
    -> (Nlmsghdr, Vec<u8>)
{
    let mut body = Vec::new();
    let ifa = Ifaddrmsg {
        ifa_family: AF_INET6,
        ifa_prefixlen: prefixlen,
        ifa_flags,
        ifa_scope: RT_SCOPE_UNIVERSE,
        ifa_index: ifindex,
    };
    let mut ifa_buf = [0u8; Ifaddrmsg::SIZE];
    ifa.write_to(&mut ifa_buf);
    body.extend_from_slice(&ifa_buf);
    put_nlattr(&mut body, ifa::IFA_LOCAL, &addr);
    let mut hdr = Nlmsghdr {
        nlmsg_len: 0, nlmsg_type: ty,
        nlmsg_flags: crate::flags::NLM_F_REQUEST | crate::flags::NLM_F_ACK | msg_flags,
        nlmsg_seq: 77, nlmsg_pid: 91,
    };
    let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
    msg.extend_from_slice(&body);
    hdr.nlmsg_len = msg.len() as u32;
    hdr.write_to(&mut msg[..Nlmsghdr::SIZE]);
    (hdr, msg)
}

/// Re-stamp the header after appending attributes.
pub(super) fn seal(hdr: &mut Nlmsghdr, msg: &mut [u8]) {
    hdr.nlmsg_len = msg.len() as u32;
    hdr.write_to(&mut msg[..Nlmsghdr::SIZE]);
}

pub(super) fn cacheinfo_attr(msg: &mut Vec<u8>, preferred: u32, valid: u32) {
    let mut ci = [0u8; 16];
    ci[0..4].copy_from_slice(&preferred.to_ne_bytes());
    ci[4..8].copy_from_slice(&valid.to_ne_bytes());
    ci[8..12].copy_from_slice(&0x1234_5678u32.to_ne_bytes());
    ci[12..16].copy_from_slice(&0x8765_4321u32.to_ne_bytes());
    put_nlattr(msg, ifa::IFA_CACHEINFO, &ci);
}

pub(super) struct Fixture {
    pub(super) iface: net::NetIfaceId,
    pub(super) ifindex: u32,
    _domain: net::hosted_fixture::InitNetDomain,
}

pub(super) fn fixture() -> Fixture {
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let iface = net::global_stack().ifaces.register_in_ns(Arc::new(MovingDev), 0);
    let ifindex = visible_ifindex(iface, 0);
    Fixture { iface, ifindex, _domain: domain }
}

impl Drop for Fixture {
    fn drop(&mut self) { let _ = net::global_stack().ifaces.unregister(self.iface); }
}

pub(super) fn row_for(iface: net::NetIfaceId, addr: [u8; 16]) -> Option<net::stack_ipv6::Ipv6IfaceAddr> {
    net::global_stack().v6_addr_snapshot_in(0).into_iter()
        .find(|(id, row)| *id == iface && row.addr.0 == addr).map(|(_, row)| row)
}

