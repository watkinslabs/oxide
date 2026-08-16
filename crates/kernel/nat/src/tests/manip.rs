// Packet rewriting. Every assertion here is checked by rebuilding the
// checksum from scratch over the mutated packet: an incremental update that
// looks plausible but is wrong produces a packet every receiver silently
// discards, and no field comparison would notice.

use conntrack::tuple::{InetAddr, ProtoPart, Tuple, TupleEnd};
use conntrack::uapi::*;

use crate::manip::*;
use crate::uapi::*;
use super::range::tcp;

const IPV4_HDR: usize = 20;

/// Straight ones-complement sum over a byte range, for verification.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < bytes.len() { sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32; i += 2; }
    if i < bytes.len() { sum += (bytes[i] as u32) << 8; }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

fn pseudo_sum(src: &[u8], dst: &[u8], proto: u8, l4_len: usize) -> u32 {
    let mut sum = 0u32;
    for c in src.chunks(2) { sum += u16::from_be_bytes([c[0], c[1]]) as u32; }
    for c in dst.chunks(2) { sum += u16::from_be_bytes([c[0], c[1]]) as u32; }
    sum += proto as u32;
    sum += l4_len as u32;
    sum
}

fn l4_checksum(buf: &[u8], l4_off: usize, csum_off: usize, proto: u8, v6: bool) -> u16 {
    let (src, dst) = if v6 { (&buf[8..24], &buf[24..40]) } else { (&buf[12..16], &buf[16..20]) };
    let mut work = buf[l4_off..].to_vec();
    work[csum_off] = 0;
    work[csum_off + 1] = 0;
    let mut sum = pseudo_sum(src, dst, proto, work.len());
    let mut i = 0;
    while i + 1 < work.len() { sum += u16::from_be_bytes([work[i], work[i + 1]]) as u32; i += 2; }
    if i < work.len() { sum += (work[i] as u32) << 8; }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

/// IPv4 + TCP packet with correct checksums.
fn v4_tcp_packet(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8])
    -> alloc::vec::Vec<u8>
{
    let l4_len = 20 + payload.len();
    let total = IPV4_HDR + l4_len;
    let mut b = alloc::vec![0u8; total];
    b[0] = 0x45;
    b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    b[8] = 64;
    b[9] = IPPROTO_TCP;
    b[12..16].copy_from_slice(&src);
    b[16..20].copy_from_slice(&dst);
    let ck = checksum(&b[..IPV4_HDR]);
    b[10..12].copy_from_slice(&ck.to_be_bytes());
    b[IPV4_HDR..IPV4_HDR + 2].copy_from_slice(&sport.to_be_bytes());
    b[IPV4_HDR + 2..IPV4_HDR + 4].copy_from_slice(&dport.to_be_bytes());
    b[IPV4_HDR + 12] = 5 << 4;
    b[IPV4_HDR + 20..].copy_from_slice(payload);
    let ck = l4_checksum(&b, IPV4_HDR, 16, IPPROTO_TCP, false);
    b[IPV4_HDR + 16..IPV4_HDR + 18].copy_from_slice(&ck.to_be_bytes());
    b
}

fn v4_udp_packet(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8],
                 zero_csum: bool) -> alloc::vec::Vec<u8>
{
    let l4_len = 8 + payload.len();
    let total = IPV4_HDR + l4_len;
    let mut b = alloc::vec![0u8; total];
    b[0] = 0x45;
    b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    b[8] = 64;
    b[9] = IPPROTO_UDP;
    b[12..16].copy_from_slice(&src);
    b[16..20].copy_from_slice(&dst);
    let ck = checksum(&b[..IPV4_HDR]);
    b[10..12].copy_from_slice(&ck.to_be_bytes());
    b[IPV4_HDR..IPV4_HDR + 2].copy_from_slice(&sport.to_be_bytes());
    b[IPV4_HDR + 2..IPV4_HDR + 4].copy_from_slice(&dport.to_be_bytes());
    b[IPV4_HDR + 4..IPV4_HDR + 6].copy_from_slice(&(l4_len as u16).to_be_bytes());
    b[IPV4_HDR + 8..].copy_from_slice(payload);
    if !zero_csum {
        let ck = l4_checksum(&b, IPV4_HDR, 6, IPPROTO_UDP, false);
        b[IPV4_HDR + 6..IPV4_HDR + 8].copy_from_slice(&ck.to_be_bytes());
    }
    b
}

fn assert_v4_header_valid(b: &[u8]) {
    assert_eq!(checksum(&b[..IPV4_HDR]), 0, "IPv4 header checksum must verify");
}

#[test]
fn source_translation_rewrites_the_address_and_port_and_both_checksums() {
    let mut b = v4_tcp_packet([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80, b"hello");
    assert_v4_header_valid(&b);
    let target = tcp([203, 0, 113, 5], 40000, [93, 184, 216, 34], 80);
    manip_ipv4(&mut b, IPV4_HDR, &target, NF_NAT_MANIP_SRC).unwrap();

    assert_eq!(&b[12..16], &[203, 0, 113, 5]);
    assert_eq!(u16::from_be_bytes([b[IPV4_HDR], b[IPV4_HDR + 1]]), 40000);
    assert_eq!(&b[16..20], &[93, 184, 216, 34], "the far end must be untouched");
    assert_eq!(u16::from_be_bytes([b[IPV4_HDR + 2], b[IPV4_HDR + 3]]), 80);
    assert_v4_header_valid(&b);
    let want = l4_checksum(&b, IPV4_HDR, 16, IPPROTO_TCP, false);
    let got = u16::from_be_bytes([b[IPV4_HDR + 16], b[IPV4_HDR + 17]]);
    assert_eq!(got, want, "the TCP checksum must still cover the packet");
}

#[test]
fn destination_translation_rewrites_only_the_far_end() {
    let mut b = v4_tcp_packet([10, 0, 0, 1], 1234, [203, 0, 113, 5], 80, b"x");
    let target = tcp([10, 0, 0, 1], 1234, [10, 0, 0, 50], 8080);
    manip_ipv4(&mut b, IPV4_HDR, &target, NF_NAT_MANIP_DST).unwrap();
    assert_eq!(&b[16..20], &[10, 0, 0, 50]);
    assert_eq!(u16::from_be_bytes([b[IPV4_HDR + 2], b[IPV4_HDR + 3]]), 8080);
    assert_eq!(&b[12..16], &[10, 0, 0, 1]);
    assert_eq!(u16::from_be_bytes([b[IPV4_HDR], b[IPV4_HDR + 1]]), 1234);
    assert_v4_header_valid(&b);
    assert_eq!(u16::from_be_bytes([b[IPV4_HDR + 16], b[IPV4_HDR + 17]]),
               l4_checksum(&b, IPV4_HDR, 16, IPPROTO_TCP, false));
}

#[test]
fn a_translation_that_changes_nothing_leaves_the_bytes_identical() {
    let orig = v4_tcp_packet([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80, b"payload");
    let mut b = orig.clone();
    let target = tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);
    manip_ipv4(&mut b, IPV4_HDR, &target, NF_NAT_MANIP_SRC).unwrap();
    assert_eq!(b, orig, "an identity rewrite must not perturb any checksum");
}

#[test]
fn a_round_trip_through_both_directions_restores_the_packet() {
    // Out through SNAT, back through the reverse: the client must receive
    // exactly what it would have without the NAT in the path.
    let orig = v4_tcp_packet([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80, b"data");
    let mut b = orig.clone();
    let out = tcp([203, 0, 113, 5], 40000, [93, 184, 216, 34], 80);
    manip_ipv4(&mut b, IPV4_HDR, &out, NF_NAT_MANIP_SRC).unwrap();
    let back = tcp([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80);
    manip_ipv4(&mut b, IPV4_HDR, &back, NF_NAT_MANIP_SRC).unwrap();
    assert_eq!(b, orig);
}

#[test]
fn udp_with_no_checksum_keeps_none() {
    // A zero UDP checksum means "not computed". Writing a real one over it is
    // wrong; writing a zero that resulted from arithmetic is worse.
    let mut b = v4_udp_packet([10, 0, 0, 1], 1234, [93, 184, 216, 34], 53, b"q", true);
    let mut target = tcp([203, 0, 113, 5], 40000, [93, 184, 216, 34], 53);
    target.protonum = IPPROTO_UDP;
    manip_ipv4(&mut b, IPV4_HDR, &target, NF_NAT_MANIP_SRC).unwrap();
    assert_eq!(u16::from_be_bytes([b[IPV4_HDR + 6], b[IPV4_HDR + 7]]), 0);
    assert_eq!(u16::from_be_bytes([b[IPV4_HDR], b[IPV4_HDR + 1]]), 40000);
    assert_v4_header_valid(&b);
}

#[test]
fn udp_with_a_checksum_keeps_a_valid_one() {
    let mut b = v4_udp_packet([10, 0, 0, 1], 1234, [93, 184, 216, 34], 53, b"query", false);
    let mut target = tcp([203, 0, 113, 5], 40000, [93, 184, 216, 34], 53);
    target.protonum = IPPROTO_UDP;
    manip_ipv4(&mut b, IPV4_HDR, &target, NF_NAT_MANIP_SRC).unwrap();
    let got = u16::from_be_bytes([b[IPV4_HDR + 6], b[IPV4_HDR + 7]]);
    assert_ne!(got, 0, "a computed zero must be written as all-ones instead");
    assert_eq!(got, l4_checksum(&b, IPV4_HDR, 6, IPPROTO_UDP, false));
}

#[test]
fn a_zero_result_is_written_as_all_ones() {
    assert_eq!(udp_csum_fixup(0), 0xffff);
    assert_eq!(udp_csum_fixup(0x1234), 0x1234);
}

#[test]
fn icmp_rewrites_the_identifier_not_a_port() {
    let mut b = alloc::vec![0u8; IPV4_HDR + 8];
    b[0] = 0x45;
    b[2..4].copy_from_slice(&((IPV4_HDR + 8) as u16).to_be_bytes());
    b[9] = IPPROTO_ICMP;
    b[12..16].copy_from_slice(&[10, 0, 0, 1]);
    b[16..20].copy_from_slice(&[93, 184, 216, 34]);
    let ck = checksum(&b[..IPV4_HDR]);
    b[10..12].copy_from_slice(&ck.to_be_bytes());
    b[IPV4_HDR] = 8;
    b[IPV4_HDR + 4..IPV4_HDR + 6].copy_from_slice(&100u16.to_be_bytes());
    let ck = checksum(&b[IPV4_HDR..]);
    b[IPV4_HDR + 2..IPV4_HDR + 4].copy_from_slice(&ck.to_be_bytes());

    let target = Tuple {
        src: TupleEnd { addr: InetAddr::v4([203, 0, 113, 5]),
                        proto: ProtoPart::icmp(4242, 0, 0) },
        dst: TupleEnd { addr: InetAddr::v4([93, 184, 216, 34]),
                        proto: ProtoPart::icmp(0, 8, 0) },
        l3num: NFPROTO_IPV4, protonum: IPPROTO_ICMP, zone: 0,
    };
    manip_ipv4(&mut b, IPV4_HDR, &target, NF_NAT_MANIP_SRC).unwrap();
    assert_eq!(u16::from_be_bytes([b[IPV4_HDR + 4], b[IPV4_HDR + 5]]), 4242);
    assert_eq!(b[IPV4_HDR], 8, "the message type is not a port and must not move");
    assert_v4_header_valid(&b);
    // The ICMPv4 checksum has no pseudo-header, so the address change must NOT
    // have been folded into it.
    assert_eq!(checksum(&b[IPV4_HDR..]), 0);
}

#[test]
fn ipv6_rewrites_the_address_with_no_header_checksum() {
    const V6_HDR: usize = 40;
    let payload = b"hi";
    let l4_len = 20 + payload.len();
    let mut b = alloc::vec![0u8; V6_HDR + l4_len];
    b[0] = 0x60;
    b[4..6].copy_from_slice(&(l4_len as u16).to_be_bytes());
    b[6] = IPPROTO_TCP;
    b[7] = 64;
    b[8..24].copy_from_slice(&{ let mut a = [0u8; 16]; a[0] = 0x20; a[15] = 1; a });
    b[24..40].copy_from_slice(&{ let mut a = [0u8; 16]; a[0] = 0x20; a[15] = 2; a });
    b[V6_HDR..V6_HDR + 2].copy_from_slice(&1234u16.to_be_bytes());
    b[V6_HDR + 2..V6_HDR + 4].copy_from_slice(&80u16.to_be_bytes());
    b[V6_HDR + 12] = 5 << 4;
    b[V6_HDR + 20..].copy_from_slice(payload);
    let ck = l4_checksum(&b, V6_HDR, 16, IPPROTO_TCP, true);
    b[V6_HDR + 16..V6_HDR + 18].copy_from_slice(&ck.to_be_bytes());

    let mut new_src = [0u8; 16]; new_src[0] = 0x20; new_src[1] = 0x0d; new_src[15] = 9;
    let target = Tuple {
        src: TupleEnd { addr: InetAddr::v6(new_src), proto: ProtoPart::port(40000) },
        dst: TupleEnd { addr: InetAddr::v6({ let mut a = [0u8; 16]; a[0] = 0x20; a[15] = 2; a }),
                        proto: ProtoPart::port(80) },
        l3num: NFPROTO_IPV6, protonum: IPPROTO_TCP, zone: 0,
    };
    manip_ipv6(&mut b, V6_HDR, &target, NF_NAT_MANIP_SRC).unwrap();
    assert_eq!(&b[8..24], &new_src);
    assert_eq!(u16::from_be_bytes([b[V6_HDR], b[V6_HDR + 1]]), 40000);
    assert_eq!(u16::from_be_bytes([b[V6_HDR + 16], b[V6_HDR + 17]]),
               l4_checksum(&b, V6_HDR, 16, IPPROTO_TCP, true),
               "the IPv6 pseudo-header covers the whole 16-byte address");
}

#[test]
fn a_truncated_packet_is_refused_rather_than_read_past_its_end() {
    let mut b = alloc::vec![0u8; 10];
    let target = tcp([203, 0, 113, 5], 40000, [93, 184, 216, 34], 80);
    assert_eq!(manip_ipv4(&mut b, IPV4_HDR, &target, NF_NAT_MANIP_SRC),
               Err(ManipError::Truncated));
    let mut b = alloc::vec![0u8; IPV4_HDR + 4];
    b[0] = 0x45;
    assert_eq!(manip_ipv4(&mut b, IPV4_HDR, &target, NF_NAT_MANIP_SRC),
               Err(ManipError::Truncated));
}

#[test]
fn incremental_checksum_updates_agree_with_a_full_recompute() {
    // Exercised over a spread of values because an incremental update that is
    // right for one pair can be wrong across the ones-complement wrap.
    for (old, new) in [(0u16, 1u16), (0xffff, 0), (0x1234, 0x8765), (80, 8080),
                       (0x8000, 0x7fff), (65535, 65535)]
    {
        let mut body = alloc::vec![0x5au8, 0xa5, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef];
        body[0..2].copy_from_slice(&old.to_be_bytes());
        let ck = checksum(&body);
        body[0..2].copy_from_slice(&new.to_be_bytes());
        assert_eq!(csum_replace2(ck, old, new), checksum(&body),
            "old={old:#x} new={new:#x}");
    }
    for (old, new) in [(0u32, 1u32), (0xffff_ffff, 0), (0x0a000001, 0xcb007105)] {
        let mut body = alloc::vec![0u8; 8];
        body[0..4].copy_from_slice(&old.to_be_bytes());
        body[4..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let ck = checksum(&body);
        body[0..4].copy_from_slice(&new.to_be_bytes());
        assert_eq!(csum_replace4(ck, old, new), checksum(&body),
            "old={old:#x} new={new:#x}");
    }
}

#[test]
fn the_sctp_checksum_is_not_updated_incrementally() {
    // It is a CRC over the whole packet, so folding a field difference into it
    // would produce a value every receiver rejects.
    let l = l4_layout(IPPROTO_SCTP).unwrap();
    assert_eq!(l.checksum, None);
    assert_eq!(l.src_port, Some(0));
    let l = l4_layout(IPPROTO_TCP).unwrap();
    assert_eq!(l.checksum, Some(16));
    assert!(l.pseudo_header);
    let l = l4_layout(IPPROTO_ICMP).unwrap();
    assert!(!l.pseudo_header, "ICMPv4 has no pseudo-header");
    let l = l4_layout(IPPROTO_ICMPV6).unwrap();
    assert!(l.pseudo_header, "ICMPv6 does");
    assert_eq!(l4_layout(47), None);
}

#[test]
fn dispatch_picks_the_family_from_the_target() {
    let mut b = v4_tcp_packet([10, 0, 0, 1], 1234, [93, 184, 216, 34], 80, b"z");
    let target = tcp([203, 0, 113, 5], 40000, [93, 184, 216, 34], 80);
    manip_packet(&mut b, IPV4_HDR, &target, NF_NAT_MANIP_SRC).unwrap();
    assert_eq!(&b[12..16], &[203, 0, 113, 5]);
}
