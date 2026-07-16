use super::*;

fn ipv4(next: u8, transport_len: usize, payload: usize) -> Vec<u8> {
    let mut frame = alloc::vec![0u8; 14 + 20 + transport_len + payload];
    frame[12..14].copy_from_slice(&ETH_IPV4.to_be_bytes());
    frame[14] = 0x45; frame[23] = next;
    frame[16..18].copy_from_slice(&((20 + transport_len + payload) as u16).to_be_bytes());
    frame[26..30].copy_from_slice(&[10, 0, 0, 1]);
    frame[30..34].copy_from_slice(&[10, 0, 0, 2]);
    frame
}

fn tcp4(payload: usize) -> Vec<u8> {
    let mut frame = ipv4(IP_TCP, 24, payload);
    frame[46] = 0x60; frame[47] = 0x99;
    frame
}

fn udp4(payload: usize) -> Vec<u8> {
    let mut frame = ipv4(IP_UDP, 8, payload);
    frame[38..40].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
    frame
}

fn ipv6_udp(payload: usize, hop: bool) -> Vec<u8> {
    let ext = if hop { 8 } else { 0 };
    let mut frame = alloc::vec![0u8; 14 + 40 + ext + 8 + payload];
    frame[12..14].copy_from_slice(&ETH_IPV6.to_be_bytes()); frame[14] = 0x60;
    frame[18..20].copy_from_slice(&((ext + 8 + payload) as u16).to_be_bytes());
    frame[20] = if hop { IP6_HOP } else { IP_UDP };
    frame[22..38].copy_from_slice(&[1; 16]); frame[38..54].copy_from_slice(&[2; 16]);
    let udp = 54 + ext;
    if hop { frame[54] = IP_UDP; }
    frame[udp + 4..udp + 6].copy_from_slice(&((8 + payload) as u16).to_be_bytes());
    frame
}

fn input(header: VirtioHeader, body: &[u8]) -> Vec<u8> {
    let mut input = header.encode(VNET_HEADER_LEN); input.extend_from_slice(body); input
}

fn err(header: VirtioHeader, body: &[u8]) -> Option<crate::NetError> {
    prepare(&input(header, body), VNET_HEADER_LEN, usize::MAX).err()
}

#[test]
fn tcp_uses_doff_not_hdr_len_for_segment_boundary() {
    let body = tcp4(20);
    let header = VirtioHeader { flags: F_NEEDS_CSUM, gso_type: GSO_TCPV4,
        hdr_len: 54, gso_size: 8, csum_start: 34, csum_offset: 16 };
    let prepared = prepare(&input(header, &body), VNET_HEADER_LEN, 70).unwrap();
    assert_eq!(prepared.frames.len(), 3);
    assert_eq!(prepared.frames[0].len(), 14 + 20 + 24 + 8);
    assert_eq!(u32::from_be_bytes(prepared.frames[1][38..42].try_into().unwrap()), 8);
    assert_eq!(prepared.frames[0][47] & 0x09, 0);
    assert_eq!(prepared.frames[2][47] & 0x09, 0x09);
}

#[test]
fn wrong_protocol_and_partial_offsets_are_rejected() {
    let tcp = tcp4(20);
    let base = VirtioHeader { flags: F_NEEDS_CSUM, gso_type: GSO_TCPV4,
        hdr_len: 54, gso_size: 8, csum_start: 34, csum_offset: 16 };
    let mut wrong_proto = tcp.clone(); wrong_proto[23] = IP_UDP;
    assert_eq!(err(base, &wrong_proto), Some(crate::NetError::Einval));
    assert_eq!(err(VirtioHeader { csum_start: 35, ..base }, &tcp), Some(crate::NetError::Einval));
    assert_eq!(err(VirtioHeader { csum_offset: 6, ..base }, &tcp), Some(crate::NetError::Einval));

    let udp = udp4(20);
    let uso = VirtioHeader { flags: F_NEEDS_CSUM, gso_type: GSO_UDP_L4,
        hdr_len: 42, gso_size: 8, csum_start: 34, csum_offset: 6 };
    assert_eq!(err(VirtioHeader { csum_offset: 7, ..uso }, &udp), Some(crate::NetError::Einval));
    assert_eq!(err(VirtioHeader { flags: 0, ..uso }, &udp), Some(crate::NetError::Einval));
}

#[test]
fn ipv6_extensions_are_parsed_and_malformed_chains_rejected() {
    let body = ipv6_udp(20, true);
    let header = VirtioHeader { flags: F_NEEDS_CSUM, gso_type: GSO_UDP_L4,
        hdr_len: 70, gso_size: 8, csum_start: 62, csum_offset: 6 };
    let prepared = prepare(&input(header, &body), VNET_HEADER_LEN, 1518).unwrap();
    assert_eq!(prepared.frames.len(), 3);
    assert!(prepared.frames.iter().all(|frame| frame[20] == IP6_HOP && frame[54] == IP_UDP));

    let mut malformed = body.clone(); malformed[55] = 20;
    assert_eq!(err(header, &malformed), Some(crate::NetError::Einval));
    let mut fragmented = body.clone(); fragmented[54] = IP6_FRAGMENT;
    assert_eq!(err(header, &fragmented), Some(crate::NetError::Einval));
}

#[test]
fn ipv6_ufo_inserts_fragment_header() {
    let body = ipv6_udp(24, false);
    let header = VirtioHeader { flags: F_NEEDS_CSUM, gso_type: GSO_UDP,
        hdr_len: 62, gso_size: 16, csum_start: 54, csum_offset: 6 };
    let prepared = prepare(&input(header, &body), VNET_HEADER_LEN, 1518).unwrap();
    assert_eq!(prepared.frames.len(), 2);
    assert!(prepared.frames.iter().all(|frame| frame[20] == IP6_FRAGMENT && frame[54] == IP_UDP));
    assert_eq!(u16::from_be_bytes([prepared.frames[0][56], prepared.frames[0][57]]), 1);
    assert_eq!(u16::from_be_bytes([prepared.frames[1][56], prepared.frames[1][57]]), 16);
    assert_ne!(&prepared.frames[0][68..70], &[0, 0]);
}

#[test]
fn hdr_len_is_a_hint_but_must_fit() {
    let body = tcp4(20);
    let header = VirtioHeader { flags: 0, gso_type: GSO_TCPV4,
        hdr_len: 1, gso_size: 8, csum_start: 0, csum_offset: 0 };
    assert_eq!(prepare(&input(header, &body), VNET_HEADER_LEN, 1518).unwrap().frames.len(), 3);
    assert_eq!(err(VirtioHeader { hdr_len: body.len() as u16 + 1, ..header }, &body),
        Some(crate::NetError::Einval));
}

#[test]
fn sizes_flags_and_udp_segment_limit_follow_linux() {
    let tcp = tcp4(20);
    let base = VirtioHeader { flags: 0x80, gso_type: GSO_TCPV4,
        hdr_len: 58, gso_size: 8, csum_start: 0, csum_offset: 0 };
    assert!(prepare(&input(base, &tcp), VNET_HEADER_LEN, 1518).is_ok());
    assert_eq!(err(VirtioHeader { gso_type: GSO_ECN, ..base }, &tcp), Some(crate::NetError::Einval));
    assert_eq!(err(VirtioHeader { gso_size: 0, ..base }, &tcp), Some(crate::NetError::Einval));
    assert_eq!(err(VirtioHeader { gso_size: GSO_BY_FRAGS, ..base }, &tcp), Some(crate::NetError::Einval));

    let udp = udp4(UDP_MAX_SEGMENTS + 1);
    let uso = VirtioHeader { flags: F_NEEDS_CSUM, gso_type: GSO_UDP_L4,
        hdr_len: 42, gso_size: 1, csum_start: 34, csum_offset: 6 };
    assert_eq!(err(uso, &udp), Some(crate::NetError::Einval));
}

#[test]
fn zero_checksum_is_mangled_and_degenerate_gso_completes_partial() {
    let mut raw = alloc::vec![0u8; 4]; raw[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
    let plain = VirtioHeader { flags: F_NEEDS_CSUM, gso_type: GSO_NONE,
        hdr_len: 4, gso_size: 0, csum_start: 0, csum_offset: 0 };
    let prepared = prepare(&input(plain, &raw), VNET_HEADER_LEN, 1518).unwrap();
    assert_eq!(&prepared.frames[0][0..2], &u16::MAX.to_be_bytes());

    let body = tcp4(4);
    let gso = VirtioHeader { flags: F_NEEDS_CSUM, gso_type: GSO_TCPV4,
        hdr_len: 58, gso_size: 8, csum_start: 34, csum_offset: 16 };
    let prepared = prepare(&input(gso, &body), VNET_HEADER_LEN, 1518).unwrap();
    assert_eq!(prepared.frames.len(), 1);
    assert_ne!(&prepared.frames[0][50..52], &[0, 0]);
}

#[test]
fn invalid_header_and_unsegmented_oversize_are_rejected() {
    assert_eq!(prepare(&[0; 9], VNET_HEADER_LEN, 1518).err(), Some(crate::NetError::Einval));
    let mut bytes = VirtioHeader::default().encode(VNET_HEADER_LEN);
    bytes.extend_from_slice(&alloc::vec![0; 1519]);
    assert_eq!(prepare(&bytes, VNET_HEADER_LEN, 1518).err(), Some(crate::NetError::Emsgsize));
}
