// `IPPROTO_IPV6` option coverage: sticky.

use alloc::vec::Vec;
use syscall::errno::Errno;
use super::super::hdr;
use super::super::state::{Ipv6Opts, Sticky};
use super::super::uapi::*;
use super::*;

// ---- sticky extension headers -------------------------------------------

#[test]
fn hop_by_hop_and_destination_options_are_privileged() {
    for name in [IPV6_HOPOPTS, IPV6_DSTOPTS, IPV6_RTHDRDSTOPTS] {
        assert_eq!(hdr::admit(name, &[0u8; 8], none()), Err(Errno::Eperm), "{name}");
        assert!(hdr::admit(name, &[0, 0, 1, 0, 0, 0, 0, 0], net_raw()).is_ok(), "{name}");
    }
    // The routing header is not.
    assert!(hdr::admit(IPV6_RTHDR, &[], none()).is_ok());
}

#[test]
fn an_empty_area_removes_the_stored_header() {
    assert_eq!(hdr::admit(IPV6_HOPOPTS, &[], net_raw()), Ok(None));
    let opts = Ipv6Opts::default();
    opts.set_header(Sticky::HopOpts, Some(Vec::from([0u8; 8])));
    assert!(opts.header(Sticky::HopOpts).is_some());
    opts.set_header(Sticky::HopOpts, None);
    assert!(opts.header(Sticky::HopOpts).is_none());
}

#[test]
fn a_header_area_must_be_eight_byte_aligned_and_bounded() {
    assert_eq!(hdr::admit(IPV6_HOPOPTS, &[0u8; 7], net_raw()), Err(Errno::Einval));
    assert_eq!(hdr::admit(IPV6_HOPOPTS, &[0u8; 12], net_raw()), Err(Errno::Einval));
    assert_eq!(hdr::admit(IPV6_HOPOPTS, &alloc::vec![0u8; 8 * 256], net_raw()),
        Err(Errno::Einval));
    // A declared length past the bytes supplied is refused.
    assert_eq!(hdr::admit(IPV6_HOPOPTS, &[0, 3, 0, 0, 0, 0, 0, 0], net_raw()),
        Err(Errno::Einval));
}

#[test]
fn a_sticky_routing_header_is_the_segment_routing_form_only() {
    // Type zero, the deprecated source route, is refused.
    let type0 = [0u8, 2, IPV6_SRCRT_TYPE_0, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(hdr::admit(IPV6_RTHDR, &type0, net_raw()), Err(Errno::Einval));
    // A single-segment routing header in the segment-routing form: header
    // length four (five eight-byte units minus one), one segment.
    let mut srh = alloc::vec![0u8; 24];
    srh[1] = 2;
    srh[2] = IPV6_SRCRT_TYPE_4;
    srh[3] = 0;
    srh[4] = 0;
    assert!(hdr::validate_srh(&srh));
    assert!(hdr::admit(IPV6_RTHDR, &srh, none()).is_ok());
    // Segments left past the last entry is malformed.
    srh[3] = 5;
    assert!(!hdr::validate_srh(&srh));
}

#[test]
fn the_header_chain_is_published_in_wire_order() {
    let opts = Ipv6Opts::default();
    let area = |tag: u8| Some(alloc::vec![tag, 0, 0, 0, 0, 0, 0, 0]);
    opts.set_header(Sticky::DstOpts, area(4));
    opts.set_header(Sticky::HopOpts, area(1));
    opts.set_header(Sticky::Rthdr, area(3));
    opts.set_header(Sticky::RthdrDstOpts, area(2));
    let chain: Vec<u8> = opts.header_chain().into_iter().map(|(_, b)| b[0]).collect();
    assert_eq!(chain, alloc::vec![1, 2, 3, 4]);
}
