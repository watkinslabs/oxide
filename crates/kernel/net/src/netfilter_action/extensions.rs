use super::*;

fn tcp_option(p: &[u8], family: u8, want: u8) -> Option<(usize, usize)> {
    let at = checksum::transport_offset(p, family)?;
    let segment = p.get(at..)?;
    let header_len = (*segment.get(12)? >> 4) as usize * 4;
    if header_len < crate::tcp_hdr::TCP_HDR_MIN_LEN || header_len > segment.len() {
        return None;
    }
    let mut i = crate::tcp_hdr::TCP_HDR_MIN_LEN;
    while i < header_len {
        let kind = *segment.get(i)?;
        if kind == 0 { return None; }
        if kind == want {
            let len = if kind == 1 { 1 } else { *segment.get(i + 1)? as usize };
            if len < 2 || i + len > header_len { return None; }
            return Some((at + i, len));
        }
        let len = if kind == 1 { 1 } else { *segment.get(i + 1)? as usize };
        if len < 2 || i + len > header_len { return None; }
        i += len;
    }
    None
}

pub(super) fn apply_exthdr_set(p: &mut crate::pkt::Pkt, family: u8, op: u32, htype: u8,
                    offset: usize, data: &[u8]) -> Result<(), ApplyError> {
    match op {
        // NFT_EXTHDR_OP_TCPOPT. Linux only permits two- and four-byte writes
        // to TCP options; the parser has already enforced that shape.
        1 => {
            let l4 = checksum::transport_offset(p.data(), family).ok_or(ApplyError::Invalid)?;
            let (at, len) = tcp_option(p.data(), family, htype).ok_or(ApplyError::Invalid)?;
            if offset.checked_add(data.len()).ok_or(ApplyError::Invalid)? > len {
                return Err(ApplyError::Invalid);
            }
            let start = at + offset;
            p.data_mut()[start..start + data.len()].copy_from_slice(data);
            checksum::repair_payload_checksum(p, family, PAYLOAD_TRANSPORT_HEADER, l4, 16)
        }
        // NFT_EXTHDR_OP_IPV4. Only the supported IPv4 options are exposed by
        // the evaluator, and they live inside the variable-length IP header.
        2 => {
            if family != crate::netfilter_hook::NFPROTO_IPV4 { return Err(ApplyError::Unsupported); }
            let ihl = (*p.data().first().ok_or(ApplyError::Invalid)? & 0x0f) as usize * 4;
            let (at, len) = ipv4_option(p.data(), htype).ok_or(ApplyError::Invalid)?;
            if at + offset + data.len() > at + len || at + offset + data.len() > ihl {
                return Err(ApplyError::Invalid);
            }
            let start = at + offset;
            p.data_mut()[start..start + data.len()].copy_from_slice(data);
            checksum::repair_payload_checksum(p, family, PAYLOAD_NETWORK_HEADER, 0, 10)
        }
        _ => Err(ApplyError::Unsupported),
    }
}

fn ipv4_option(p: &[u8], want: u8) -> Option<(usize, usize)> {
    if p.len() < 20 { return None; }
    let ihl = (p[0] & 0x0f) as usize * 4;
    if ihl < 20 || ihl > p.len() { return None; }
    let mut i = 20;
    while i < ihl {
        let kind = p[i];
        if kind == 0 { return None; }
        if kind == want {
            let len = p.get(i + 1).copied()? as usize;
            if len < 2 || i + len > ihl { return None; }
            return Some((i, len));
        }
        if kind == 1 { i += 1; continue; }
        let len = p.get(i + 1).copied()? as usize;
        if len < 2 || i + len > ihl { return None; }
        i += len;
    }
    None
}

pub(super) fn apply_exthdr_strip(p: &mut crate::pkt::Pkt, family: u8, op: u32, htype: u8)
    -> Result<(), ApplyError> {
    match op {
        1 => {
            let l4 = match checksum::transport_offset(p.data(), family) {
                Some(l4) => l4,
                None => return Ok(()),
            };
            let (at, len) = match tcp_option(p.data(), family, htype) {
                Some(found) => found,
                None => return Ok(()),
            };
            p.data_mut()[at..at + len].fill(1);
            checksum::repair_payload_checksum(p, family, PAYLOAD_TRANSPORT_HEADER, l4, 16)
        }
        2 => {
            if family != crate::netfilter_hook::NFPROTO_IPV4 { return Err(ApplyError::Unsupported); }
            let (at, len) = match ipv4_option(p.data(), htype) {
                Some(found) => found,
                None => return Ok(()),
            };
            p.data_mut()[at..at + len].fill(1);
            checksum::repair_payload_checksum(p, family, PAYLOAD_NETWORK_HEADER, 0, 10)
        }
        _ => Err(ApplyError::Unsupported),
    }
}


