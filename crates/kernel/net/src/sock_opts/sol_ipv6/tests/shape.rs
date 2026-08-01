// `IPPROTO_IPV6` option coverage: shape.

use syscall::errno::Errno;
use super::super::set::{self, Action, ArgClass};
use super::super::state::flag;
use super::super::uapi::*;
use super::*;

// ---- operand shape ------------------------------------------------------

#[test]
fn this_level_reads_a_whole_int_or_nothing() {
    // Unlike the IPv4 level there is no single-byte form: a short operand is
    // either refused or read as zero, never as a byte.
    for name in [IPV6_UNICAST_HOPS, IPV6_MTU, IPV6_MINHOPCOUNT, IPV6_RECVERR,
        IPV6_MTU_DISCOVER, IPV6_TCLASS, IPV6_V6ONLY]
    {
        assert_eq!(set6(name, 0, 1), Err(Errno::Einval), "{name}");
        assert_eq!(set6(name, 0, 3), Err(Errno::Einval), "{name}");
    }
    assert_eq!(set::arg_class(IPV6_RTHDR), ArgClass::Header);
    assert_eq!(set::arg_class(IPV6_PKTINFO), ArgClass::PktInfo);
    assert_eq!(set::arg_class(IPV6_FLOWLABEL_MGR), ArgClass::FlowLabel);
    assert_eq!(set::arg_class(IPV6_XFRM_POLICY), ArgClass::Policy);
    assert_eq!(set::arg_class(MCAST_JOIN_GROUP), ArgClass::Delegated);
}

#[test]
fn three_options_carry_no_width_screen_at_all() {
    // These accept a zero-length operand and read it as zero.
    assert_eq!(set6(IPV6_AUTOFLOWLABEL, 0, 0),
        Ok(Action::Flag { bit: flag::AUTOFLOWLABEL, on: false }));
    assert_eq!(set6(IPV6_DONTFRAG, 0, 0),
        Ok(Action::Flag { bit: flag::DONTFRAG, on: false }));
    assert_eq!(set6(IPV6_RECVFRAGSIZE, 0, 0),
        Ok(Action::Flag { bit: flag::RECVFRAGSIZE, on: false }));
}
