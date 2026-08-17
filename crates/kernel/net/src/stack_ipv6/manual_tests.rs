//! What a manual IPv6 address row derives from itself: its reported scope, its
//! reported flags, and when its lifetimes expire.

use crate::addr::Ipv6Addr;
use crate::iface_addr::{IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_MANAGETEMPADDR, IFA_F_NODAD,
    IFA_F_PERMANENT, IFA_F_TEMPORARY, IFA_F_TENTATIVE, INFINITY_LIFE_TIME, RT_SCOPE_HOST,
    RT_SCOPE_LINK, RT_SCOPE_SITE, RT_SCOPE_UNIVERSE};

use super::{Ipv6AddrOrigin, Ipv6AddrState, Ipv6IfaceAddr};

const SEC: u64 = 1_000_000_000;

fn row(addr: Ipv6Addr) -> Ipv6IfaceAddr {
    Ipv6IfaceAddr {
        addr, peer: None, prefixlen: 64,
        preferred: INFINITY_LIFE_TIME, valid: INFINITY_LIFE_TIME,
        preferred_until_ns: u64::MAX, valid_until_ns: u64::MAX,
        origin: Ipv6AddrOrigin::Static, state: Ipv6AddrState::Assigned,
        deprecated: false, temporary: false, user_flags: 0, proto: 0, rt_priority: 0,
        cstamp: 0, tstamp: 0, notify_pending: false,
    }
}

// The scope ladder is host, then link, then site, then universe — derived from
// the address, never taken from the setter. Site-local is its own rung: an
// implementation that only special-cases loopback and link-local reports a
// site-local address as global.
#[test]
fn the_reported_scope_is_derived_from_the_address() {
    assert_eq!(row(Ipv6Addr::LOOPBACK).rt_scope(), RT_SCOPE_HOST);
    assert_eq!(row(Ipv6Addr::from_segments([0xfe80, 0, 0, 0, 0, 0, 0, 1])).rt_scope(),
        RT_SCOPE_LINK);
    assert_eq!(row(Ipv6Addr::from_segments([0xfebf, 0, 0, 0, 0, 0, 0, 1])).rt_scope(),
        RT_SCOPE_LINK, "fe80::/10 runs to febf");
    assert_eq!(row(Ipv6Addr::from_segments([0xfec0, 0, 0, 0, 0, 0, 0, 1])).rt_scope(),
        RT_SCOPE_SITE);
    assert_eq!(row(Ipv6Addr::from_segments([0xfeff, 0, 0, 0, 0, 0, 0, 1])).rt_scope(),
        RT_SCOPE_SITE, "fec0::/10 runs to feff");
    assert_eq!(row(Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])).rt_scope(),
        RT_SCOPE_UNIVERSE);
    // A unique-local address is global scope, not site scope.
    assert_eq!(row(Ipv6Addr::from_segments([0xfd00, 0, 0, 0, 0, 0, 0, 1])).rt_scope(),
        RT_SCOPE_UNIVERSE);
    // A multicast address carries no unicast scope bit and reports universe,
    // whatever scope its own header field names.
    let mut group = [0u8; 16];
    group[0] = 0xff; group[1] = 0x02; group[15] = 1;
    assert_eq!(row(Ipv6Addr(group)).rt_scope(), RT_SCOPE_UNIVERSE);
    assert_eq!(row(Ipv6Addr::ANY).rt_scope(), RT_SCOPE_UNIVERSE);
}

// Permanence follows the valid lifetime and nothing else: a manual address with
// an infinite valid lifetime is permanent, one with a deadline is not, and an
// autoconfigured address never is.
#[test]
fn permanence_follows_the_valid_lifetime_and_the_origin() {
    let permanent = row(Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]));
    assert_eq!(permanent.flags() & IFA_F_PERMANENT, IFA_F_PERMANENT);

    let mut finite = permanent.clone();
    finite.valid_until_ns = 3600 * SEC;
    finite.valid = 3600;
    assert_eq!(finite.flags() & IFA_F_PERMANENT, 0);

    let mut slaac = permanent.clone();
    slaac.origin = Ipv6AddrOrigin::Slaac { prefix: Ipv6Addr::ANY };
    assert_eq!(slaac.flags() & IFA_F_PERMANENT, 0,
        "an autoconfigured address is never permanent");
}

// The setter's bits sit alongside the derived ones in the reported word, and
// the derived ones are computed, never carried in from the request.
#[test]
fn reported_flags_are_the_setter_bits_plus_the_derived_ones() {
    let mut r = row(Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]));
    r.user_flags = IFA_F_NODAD | IFA_F_MANAGETEMPADDR;
    assert_eq!(r.flags(), IFA_F_NODAD | IFA_F_MANAGETEMPADDR | IFA_F_PERMANENT);

    r.state = Ipv6AddrState::Tentative { dad_until_ns: None, retry_at_ns: 0,
        retrans_timer_ns: SEC };
    assert_eq!(r.flags() & IFA_F_TENTATIVE, IFA_F_TENTATIVE);
    r.state = Ipv6AddrState::DadFailed;
    assert_eq!(r.flags() & IFA_F_DADFAILED, IFA_F_DADFAILED);
    assert_eq!(r.flags() & IFA_F_TENTATIVE, 0);
    r.state = Ipv6AddrState::Assigned;

    r.deprecated = true;
    assert_eq!(r.flags() & IFA_F_DEPRECATED, IFA_F_DEPRECATED);
    r.temporary = true;
    assert_eq!(r.flags() & IFA_F_TEMPORARY, IFA_F_TEMPORARY);
}

// One deadline carrier for both origins: a manual address with a finite valid
// lifetime expires exactly the way an autoconfigured one does, so the expiry
// walker and a readback cannot disagree about when it goes away.
#[test]
fn a_manual_address_expires_against_the_same_deadline_as_an_autoconfigured_one() {
    let mut manual = row(Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]));
    manual.valid_until_ns = 10 * SEC;
    manual.preferred_until_ns = 5 * SEC;
    assert!(manual.valid_at(0));
    assert!(manual.preferred_at(0));
    assert!(manual.valid_at(5 * SEC));
    assert!(!manual.preferred_at(5 * SEC), "the preferred deadline is exclusive");
    assert!(!manual.valid_at(10 * SEC));

    let mut slaac = manual.clone();
    slaac.origin = Ipv6AddrOrigin::Slaac { prefix: Ipv6Addr::ANY };
    for now_ns in [0, 5 * SEC, 10 * SEC, 11 * SEC] {
        assert_eq!(manual.valid_at(now_ns), slaac.valid_at(now_ns), "at {now_ns}");
        assert_eq!(manual.preferred_at(now_ns), slaac.preferred_at(now_ns), "at {now_ns}");
    }
}

// The remaining lifetimes a readback reports come off the deadlines, for every
// origin. An infinite deadline reports the protocol's infinity, not a countdown.
#[test]
fn remaining_lifetimes_are_recomputed_from_the_deadlines() {
    let mut r = row(Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]));
    r.valid_until_ns = 3600 * SEC;
    r.preferred_until_ns = 1800 * SEC;
    super::addr_table::refresh_lifetimes(&mut r, 0);
    assert_eq!(r.valid, 3600);
    assert_eq!(r.preferred, 1800);
    super::addr_table::refresh_lifetimes(&mut r, 600 * SEC);
    assert_eq!(r.valid, 3000);
    assert_eq!(r.preferred, 1200);
    super::addr_table::refresh_lifetimes(&mut r, 3600 * SEC);
    assert_eq!(r.valid, 0);
    assert_eq!(r.preferred, 0);

    let mut infinite = row(Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2]));
    super::addr_table::refresh_lifetimes(&mut infinite, 9_999 * SEC);
    assert_eq!(infinite.valid, INFINITY_LIFE_TIME);
    assert_eq!(infinite.preferred, INFINITY_LIFE_TIME);
}

// IFA_ADDRESS reports the peer for a point-to-point row and the local address
// otherwise.
#[test]
fn the_reported_on_wire_address_is_the_peer_when_there_is_one() {
    let local = Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
    let peer = Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2]);
    let mut r = row(local);
    assert_eq!(r.address(), local);
    r.peer = Some(peer);
    assert_eq!(r.address(), peer);
}

// DAD runs unless the setter waived it or the device runs no neighbour
// discovery.
#[test]
fn dad_applies_unless_waived_or_the_device_has_no_neighbours() {
    use crate::netdev::iff;
    const ETHER: u32 = iff::IFF_BROADCAST | iff::IFF_MULTICAST | iff::IFF_UP;
    assert!(super::dad_applies(ETHER, 0));
    assert!(!super::dad_applies(ETHER, IFA_F_NODAD));
    assert!(!super::dad_applies(ETHER | iff::IFF_NOARP, 0));
    assert!(!super::dad_applies(iff::IFF_UP | iff::IFF_LOOPBACK, 0));
}
