use super::*;

pub(super) fn transport_offset(pkt: &[u8], family: u8) -> Option<usize> {
    if family == 10 {
        if pkt.len() < 40 { return None; }
        return match crate::ipv6_ext::walk(pkt[6], &pkt[40..]).ok()? {
            crate::ipv6_ext::ExtWalk::Done { payload, .. } => Some(pkt.len() - payload.len()),
            crate::ipv6_ext::ExtWalk::Fragment { offset: 0, payload, .. } =>
                Some(pkt.len() - payload.len()),
            crate::ipv6_ext::ExtWalk::Fragment { .. } => None,
        };
    }
    if family != 2 || pkt.len() < 20 || pkt[0] >> 4 != 4 { return None; }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || ihl > pkt.len() { return None; }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff;
    if frag != 0 { return None; }
    Some(ihl)
}

fn l4_protocol(pkt: &[u8], family: u8) -> Option<u8> {
    match family {
        crate::netfilter_hook::NFPROTO_IPV4 => pkt.get(9).copied(),
        crate::netfilter_hook::NFPROTO_IPV6 => {
            if pkt.len() < 40 { return None; }
            match crate::ipv6_ext::walk(pkt[6], &pkt[40..]).ok()? {
                crate::ipv6_ext::ExtWalk::Done { next_header, .. } => Some(next_header),
                crate::ipv6_ext::ExtWalk::Fragment { offset: 0, next_header, .. } =>
                    Some(next_header),
                crate::ipv6_ext::ExtWalk::Fragment { .. } => None,
            }
        }
        _ => None,
    }
}

pub(super) fn repair_payload_checksum(p: &mut crate::pkt::Pkt, family: u8, base: u32,
                           base_start: usize, csum_offset: usize) -> Result<(), ApplyError> {
    let bytes = p.data();
    if base == PAYLOAD_NETWORK_HEADER {
        if family != crate::netfilter_hook::NFPROTO_IPV4 || csum_offset != 10 {
            return Err(ApplyError::Unsupported);
        }
        let ihl = (bytes.first().ok_or(ApplyError::Invalid)? & 0x0f) as usize * 4;
        if ihl < 20 || ihl > bytes.len() { return Err(ApplyError::Invalid); }
        p.data_mut()[10..12].fill(0);
        let checksum = crate::ipv4::ip_checksum(&p.data()[..ihl]);
        p.data_mut()[10..12].copy_from_slice(&checksum.to_be_bytes());
        return Ok(());
    }
    if base != PAYLOAD_TRANSPORT_HEADER || csum_offset > 0xff { return Err(ApplyError::Unsupported); }
    let l4 = base_start;
    let proto = l4_protocol(bytes, family).ok_or(ApplyError::Invalid)?;
    if bytes.len() == l4 { return Err(ApplyError::Invalid); }
    let (src4, dst4, src6, dst6) = match family {
        crate::netfilter_hook::NFPROTO_IPV4 => (
            Some(crate::Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
            Some(crate::Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])), None, None),
        crate::netfilter_hook::NFPROTO_IPV6 => (
            None, None,
            Some(crate::Ipv6Addr(bytes[8..24].try_into().map_err(|_| ApplyError::Invalid)?)),
            Some(crate::Ipv6Addr(bytes[24..40].try_into().map_err(|_| ApplyError::Invalid)?))),
        _ => return Err(ApplyError::Unsupported),
    };
    let checksum_at = l4.checked_add(csum_offset).ok_or(ApplyError::Invalid)?;
    if checksum_at.checked_add(2).ok_or(ApplyError::Invalid)? > bytes.len() {
        return Err(ApplyError::Invalid);
    }
    let segment = p.data_mut().get_mut(l4..).ok_or(ApplyError::Invalid)?;
    match (family, proto, csum_offset) {
        (crate::netfilter_hook::NFPROTO_IPV4, 17, 6) => {
            if segment.len() < 8 { return Err(ApplyError::Invalid); }
            let src = src4.ok_or(ApplyError::Invalid)?; let dst = dst4.ok_or(ApplyError::Invalid)?;
            let sport = u16::from_be_bytes([segment[0], segment[1]]);
            let dport = u16::from_be_bytes([segment[2], segment[3]]);
            let payload = segment[8..].to_vec();
            crate::udp::UdpHdr::build_into(sport, dport, src, dst, &payload, segment);
        }
        (crate::netfilter_hook::NFPROTO_IPV6, 17, 6) => {
            if segment.len() < 8 { return Err(ApplyError::Invalid); }
            let src = src6.ok_or(ApplyError::Invalid)?; let dst = dst6.ok_or(ApplyError::Invalid)?;
            let sport = u16::from_be_bytes([segment[0], segment[1]]);
            let dport = u16::from_be_bytes([segment[2], segment[3]]);
            let payload = segment[8..].to_vec();
            crate::udp::build_into_v6(sport, dport, src, dst, &payload, segment);
        }
        (crate::netfilter_hook::NFPROTO_IPV4, 6, 16) => {
            if segment.len() < crate::tcp_hdr::TCP_HDR_MIN_LEN { return Err(ApplyError::Invalid); }
            let src = src4.ok_or(ApplyError::Invalid)?; let dst = dst4.ok_or(ApplyError::Invalid)?;
            let mut hdr = crate::tcp_hdr::TcpHdr {
                src_port: u16::from_be_bytes([segment[0], segment[1]]),
                dst_port: u16::from_be_bytes([segment[2], segment[3]]),
                seq: u32::from_be_bytes(segment[4..8].try_into().map_err(|_| ApplyError::Invalid)?),
                ack: u32::from_be_bytes(segment[8..12].try_into().map_err(|_| ApplyError::Invalid)?),
                data_offset: segment[12] >> 4, flags: segment[13],
                window: u16::from_be_bytes([segment[14], segment[15]]), checksum: 0,
                urg_ptr: u16::from_be_bytes([segment[18], segment[19]]),
            };
            if hdr.data_offset < 5 || segment.len() < hdr.data_offset as usize * 4 {
                return Err(ApplyError::Invalid);
            }
            hdr.build_into(src, dst, segment);
        }
        (crate::netfilter_hook::NFPROTO_IPV6, 6, 16) => {
            if segment.len() < crate::tcp_hdr::TCP_HDR_MIN_LEN { return Err(ApplyError::Invalid); }
            let src = src6.ok_or(ApplyError::Invalid)?; let dst = dst6.ok_or(ApplyError::Invalid)?;
            let mut hdr = crate::tcp_hdr::TcpHdr {
                src_port: u16::from_be_bytes([segment[0], segment[1]]),
                dst_port: u16::from_be_bytes([segment[2], segment[3]]),
                seq: u32::from_be_bytes(segment[4..8].try_into().map_err(|_| ApplyError::Invalid)?),
                ack: u32::from_be_bytes(segment[8..12].try_into().map_err(|_| ApplyError::Invalid)?),
                data_offset: segment[12] >> 4, flags: segment[13],
                window: u16::from_be_bytes([segment[14], segment[15]]), checksum: 0,
                urg_ptr: u16::from_be_bytes([segment[18], segment[19]]),
            };
            if hdr.data_offset < 5 || segment.len() < hdr.data_offset as usize * 4 {
                return Err(ApplyError::Invalid);
            }
            hdr.build_into_v6(src, dst, segment);
        }
        _ => return Err(ApplyError::Unsupported),
    }
    Ok(())
}


