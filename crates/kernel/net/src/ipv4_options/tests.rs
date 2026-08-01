// Byte-exact coverage for the emitted option area. Every expected byte string
// here is the wire form the IPv4 option contract requires, so a later change
// to the fill or fragment pass has to reproduce it.

use super::emit::{self, Header};
use crate::addr::Ipv4Addr;
use crate::ipv4::{ip_checksum, IPV4_HDR_LEN};
use crate::ipv4_options::area as options;
use crate::ipv4_options::uapi::{IPOPT_END, IPOPT_LSRR, IPOPT_NOOP, IPOPT_RA, IPOPT_RR,
    IPOPT_SSRR, IPOPT_TIMESTAMP, IPOPT_TS_PRESPEC, IPOPT_TS_TSANDADDR, IPOPT_TS_TSONLY};

const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const DST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const HOP1: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const HOP2: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const STAMP: u32 = 0x0102_0304;

fn header() -> Header {
    Header {
        src: SRC, dst: DST, proto: crate::addr::IpProto::Udp as u8,
        tos: 0, ttl: crate::ipv4::IPV4_DEFAULT_TTL, id: 0x1234, flags_frag: 0,
    }
}

fn emit(bytes: &[u8], net_raw: bool, payload_len: usize) -> alloc::vec::Vec<u8> {
    let c = options::build(bytes, net_raw).unwrap();
    let mut out = alloc::vec![0u8; emit::header_len(Some(&c))];
    emit::write_header(&mut out, &header(), Some(&c), payload_len, STAMP);
    out
}

#[test]
fn no_options_keeps_the_fixed_header() {
    assert_eq!(emit::header_len(None), IPV4_HDR_LEN);
    let mut out = alloc::vec![0u8; IPV4_HDR_LEN];
    emit::write_header(&mut out, &header(), None, 8, STAMP);
    assert_eq!(out[0], 0x45);
    assert_eq!(&out[2..4], &((IPV4_HDR_LEN + 8) as u16).to_be_bytes());
    assert_eq!(&out[16..20], &DST.octets());
    assert_eq!(ip_checksum(&out), 0);
}

#[test]
fn router_alert_rides_the_header_at_ihl_six() {
    let out = emit(&[IPOPT_RA, 4, 0, 0], false, 0);
    assert_eq!(out.len(), 24);
    assert_eq!(out[0], 0x46);
    assert_eq!(&out[2..4], &24u16.to_be_bytes());
    assert_eq!(&out[IPV4_HDR_LEN..], &[IPOPT_RA, 4, 0, 0]);
    assert_eq!(ip_checksum(&out), 0);
}

#[test]
fn record_route_takes_the_outgoing_address_and_advances_the_pointer() {
    // Three empty slots, pointer at the first.
    let mut area = alloc::vec![IPOPT_RR, 15, 4];
    area.extend_from_slice(&[0u8; 12]);
    area.push(IPOPT_END);
    let out = emit(&area, false, 0);
    assert_eq!(out.len(), IPV4_HDR_LEN + 16);
    assert_eq!(out[0], 0x49);
    // Pointer advanced past the slot the fill pass used.
    assert_eq!(&out[IPV4_HDR_LEN..IPV4_HDR_LEN + 3], &[IPOPT_RR, 15, 8]);
    assert_eq!(&out[IPV4_HDR_LEN + 3..IPV4_HDR_LEN + 7], &SRC.octets());
    // The remaining slots stay empty.
    assert_eq!(&out[IPV4_HDR_LEN + 7..IPV4_HDR_LEN + 15], &[0u8; 8]);
    assert_eq!(ip_checksum(&out), 0);
}

#[test]
fn full_record_route_leaves_the_area_untouched() {
    // Pointer past the end: the option is complete and takes no stamp.
    let mut area = alloc::vec![IPOPT_RR, 7, 8];
    area.extend_from_slice(&HOP1.octets());
    area.push(IPOPT_END);
    let out = emit(&area, false, 0);
    assert_eq!(&out[IPV4_HDR_LEN..IPV4_HDR_LEN + 3], &[IPOPT_RR, 7, 8]);
    assert_eq!(&out[IPV4_HDR_LEN + 3..IPV4_HDR_LEN + 7], &HOP1.octets());
}

#[test]
fn timestamp_only_stamps_the_time() {
    let area = [IPOPT_TIMESTAMP, 8, 5, IPOPT_TS_TSONLY, 0, 0, 0, 0];
    let out = emit(&area, false, 0);
    assert_eq!(&out[IPV4_HDR_LEN..IPV4_HDR_LEN + 4], &[IPOPT_TIMESTAMP, 8, 9, IPOPT_TS_TSONLY]);
    assert_eq!(&out[IPV4_HDR_LEN + 4..IPV4_HDR_LEN + 8], &STAMP.to_be_bytes());
}

#[test]
fn timestamp_with_address_stamps_both_halves() {
    let mut area = alloc::vec![IPOPT_TIMESTAMP, 12, 5, IPOPT_TS_TSANDADDR];
    area.extend_from_slice(&[0u8; 8]);
    let out = emit(&area, false, 0);
    assert_eq!(out[IPV4_HDR_LEN + 2], 13);
    assert_eq!(&out[IPV4_HDR_LEN + 4..IPV4_HDR_LEN + 8], &SRC.octets());
    assert_eq!(&out[IPV4_HDR_LEN + 8..IPV4_HDR_LEN + 12], &STAMP.to_be_bytes());
}

#[test]
fn prespecified_timestamp_keeps_its_address_and_stamps_behind_it() {
    let mut area = alloc::vec![IPOPT_TIMESTAMP, 12, 5, IPOPT_TS_PRESPEC];
    area.extend_from_slice(&HOP1.octets());
    area.extend_from_slice(&[0u8; 4]);
    let out = emit(&area, false, 0);
    assert_eq!(&out[IPV4_HDR_LEN + 4..IPV4_HDR_LEN + 8], &HOP1.octets());
    assert_eq!(&out[IPV4_HDR_LEN + 8..IPV4_HDR_LEN + 12], &STAMP.to_be_bytes());
}

/// The wire header of a loose source route names the FIRST hop, the option
/// list loses that hop, and the real destination lands in the last slot.
#[test]
fn loose_source_route_retargets_the_header_and_appends_the_destination() {
    let mut area = alloc::vec![IPOPT_LSRR, 11, 4];
    area.extend_from_slice(&HOP1.octets());
    area.extend_from_slice(&HOP2.octets());
    area.push(IPOPT_END);
    let c = options::build(&area, true).unwrap();
    assert_eq!(c.faddr, HOP1.octets());
    let out = emit(&area, true, 0);
    assert_eq!(out.len(), IPV4_HDR_LEN + 12);
    assert_eq!(&out[16..20], &HOP1.octets());
    assert_eq!(&out[IPV4_HDR_LEN..IPV4_HDR_LEN + 3], &[IPOPT_LSRR, 11, 4]);
    assert_eq!(&out[IPV4_HDR_LEN + 3..IPV4_HDR_LEN + 7], &HOP2.octets());
    assert_eq!(&out[IPV4_HDR_LEN + 7..IPV4_HDR_LEN + 11], &DST.octets());
    assert_eq!(ip_checksum(&out), 0);
}

#[test]
fn strict_source_route_is_reported_to_the_route_decision() {
    let mut area = alloc::vec![IPOPT_SSRR, 7, 4];
    area.extend_from_slice(&HOP1.octets());
    area.push(IPOPT_END);
    let c = options::build(&area, true).unwrap();
    assert!(emit::is_strict_route(Some(&c)));
    assert_eq!(emit::wire_dst(Some(&c), DST), HOP1);
    let loose = options::build(&[IPOPT_RA, 4, 0, 0], false).unwrap();
    assert!(!emit::is_strict_route(Some(&loose)));
    assert_eq!(emit::wire_dst(Some(&loose), DST), DST);
    assert_eq!(emit::wire_dst(None, DST), DST);
}

/// Record-route and timestamp are not copied into later fragments; the source
/// route and the router alert are. The header length never changes.
#[test]
fn later_fragments_blank_the_uncopied_options() {
    let mut area = alloc::vec![IPOPT_LSRR, 7, 4];
    area.extend_from_slice(&HOP1.octets());
    area.extend_from_slice(&[IPOPT_RR, 7, 4, 0, 0, 0, 0]);
    area.extend_from_slice(&[IPOPT_RA, 4, 0, 0]);
    area.push(IPOPT_END);
    let c = options::build(&area, true).unwrap();
    let f = emit::fragmented(&c);
    assert_eq!(f.len(), c.len());
    assert!(f.rr.is_none() && !f.rr_needaddr && !f.ts_needtime);
    assert_eq!(&f.data[7..14], &[IPOPT_NOOP; 7]);
    assert_eq!(&f.data[0..3], &[IPOPT_LSRR, 7, 4]);
    assert_eq!(&f.data[14..18], &[IPOPT_RA, 4, 0, 0]);

    let mut out = alloc::vec![0u8; emit::header_len(Some(&f))];
    emit::write_header(&mut out, &header(), Some(&f), 8, STAMP);
    // The source route still carries the real destination on every fragment.
    assert_eq!(&out[16..20], &HOP1.octets());
    assert_eq!(&out[IPV4_HDR_LEN + 3..IPV4_HDR_LEN + 7], &DST.octets());
    assert_eq!(&out[IPV4_HDR_LEN + 7..IPV4_HDR_LEN + 14], &[IPOPT_NOOP; 7]);
    assert_eq!(ip_checksum(&out), 0);
}

#[test]
fn header_length_field_tracks_the_option_area() {
    for (area, ihl) in [
        (alloc::vec![IPOPT_RA, 4, 0, 0], 6u8),
        (alloc::vec![IPOPT_NOOP], 6),
        (alloc::vec![IPOPT_TIMESTAMP, 8, 5, IPOPT_TS_TSONLY, 0, 0, 0, 0], 7),
    ] {
        let out = emit(&area, false, 0);
        assert_eq!(out[0] & 0x0f, ihl);
        assert_eq!(out.len(), ihl as usize * 4);
        assert_eq!(ip_checksum(&out), 0);
    }
}
