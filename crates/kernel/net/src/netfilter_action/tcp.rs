use super::*;

pub(super) fn apply_tcp_seq_adjust(p: &mut crate::pkt::Pkt, conn: &conntrack::Conn,
                        dir: u8, family: u8) -> Result<(), ApplyError> {
    let l4 = checksum::transport_offset(p.data(), family).ok_or(ApplyError::Invalid)?;
    let (src, dst) = packet_addresses(p.data(), family).ok_or(ApplyError::Invalid)?;
    let parsed = crate::tcp_hdr::parse_ip(&p.data()[l4..], src, dst)
        .map_err(|_| ApplyError::Invalid)?;
    let other = dir ^ 1;
    let seq = parsed.seq.wrapping_add(conn.seqadj_offset(dir, parsed.seq) as u32);
    let ack = if parsed.flags & crate::tcp_hdr::flags::ACK != 0 {
        let offset = conn.seqadj_ack_offset(other, parsed.ack);
        parsed.ack.wrapping_sub(offset as u32)
    } else { parsed.ack };
    let mut changed = seq != parsed.seq || ack != parsed.ack;
    let segment = p.data_mut().get_mut(l4..).ok_or(ApplyError::Invalid)?;
    if changed {
        segment[4..8].copy_from_slice(&seq.to_be_bytes());
        segment[8..12].copy_from_slice(&ack.to_be_bytes());
    }
    changed |= adjust_sack_options(segment, parsed.data_offset, conn, other);
    if let Some(state) = *conn.synproxy.lock() {
        changed |= adjust_timestamp_option(segment, parsed.data_offset, dir, state.tsoff);
    }
    if !changed { return Ok(()); }
    let mut header = parsed;
    header.seq = seq;
    header.ack = ack;
    header.build_into_ip(src, dst, segment);
    Ok(())
}

fn adjust_timestamp_option(segment: &mut [u8], data_offset: u8, dir: u8, offset: i32) -> bool {
    if offset == 0 { return false; }
    let end = data_offset as usize * 4;
    if end <= crate::tcp_hdr::TCP_HDR_MIN_LEN || end > segment.len() { return false; }
    let mut i = crate::tcp_hdr::TCP_HDR_MIN_LEN;
    while i < end {
        let kind = segment[i];
        if kind == crate::tcp_hdr::opt::END { return false; }
        if kind == crate::tcp_hdr::opt::NOP { i += 1; continue; }
        if i + 1 >= end { return false; }
        let len = segment[i + 1] as usize;
        if len < 2 || i + len > end { return false; }
        if kind == crate::tcp_hdr::opt::TIMESTAMP && len == 10 {
            let at = if dir == conntrack::uapi::IP_CT_DIR_REPLY { i + 2 } else { i + 6 };
            let old = u32::from_be_bytes(segment[at..at + 4].try_into().unwrap());
            let new = if dir == conntrack::uapi::IP_CT_DIR_REPLY {
                old.wrapping_sub(offset as u32)
            } else {
                old.wrapping_add(offset as u32)
            };
            segment[at..at + 4].copy_from_slice(&new.to_be_bytes());
            return new != old;
        }
        i += len;
    }
    false
}

fn adjust_sack_options(segment: &mut [u8], data_offset: u8, conn: &conntrack::Conn,
                       other: u8) -> bool {
    let end = data_offset as usize * 4;
    if end <= crate::tcp_hdr::TCP_HDR_MIN_LEN || end > segment.len() { return false; }
    let mut i = crate::tcp_hdr::TCP_HDR_MIN_LEN;
    let mut changed = false;
    while i < end {
        let kind = segment[i];
        if kind == crate::tcp_hdr::opt::END { break; }
        if kind == crate::tcp_hdr::opt::NOP { i += 1; continue; }
        if i + 1 >= end { break; }
        let len = segment[i + 1] as usize;
        if len < 2 || i + len > end { break; }
        if kind == crate::tcp_hdr::opt::SACK && len >= 10 && (len - 2) % 8 == 0 {
            let mut at = i + 2;
            while at + 8 <= i + len {
                for field in [0usize, 4usize] {
                    let old = u32::from_be_bytes(segment[at + field..at + field + 4]
                        .try_into().unwrap());
                    let new = old.wrapping_sub(conn.seqadj_ack_offset(other, old) as u32);
                    if new != old {
                        segment[at + field..at + field + 4].copy_from_slice(&new.to_be_bytes());
                        changed = true;
                    }
                }
                at += 8;
            }
        }
        i += len;
    }
    changed
}

fn packet_addresses(pkt: &[u8], family: u8)
    -> Option<(crate::addr::IpAddr, crate::addr::IpAddr)> {
    match family {
        crate::netfilter_hook::NFPROTO_IPV4 if pkt.len() >= 20 => Some((
            crate::addr::IpAddr::V4(crate::addr::Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])),
            crate::addr::IpAddr::V4(crate::addr::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])),
        )),
        crate::netfilter_hook::NFPROTO_IPV6 if pkt.len() >= 40 => Some((
            crate::addr::IpAddr::V6(crate::addr::Ipv6Addr(pkt[8..24].try_into().ok()?)),
            crate::addr::IpAddr::V6(crate::addr::Ipv6Addr(pkt[24..40].try_into().ok()?)),
        )),
        _ => None,
    }
}

