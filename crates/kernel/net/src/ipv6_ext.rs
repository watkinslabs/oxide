pub const NH_HOP_BY_HOP: u8 = 0;
pub const NH_ROUTING: u8 = 43;
pub const NH_FRAGMENT: u8 = 44;
pub const NH_NO_NEXT: u8 = 59;
pub const NH_DEST_OPTS: u8 = 60;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Ipv6ExtError { Short, BadLen, UnsupportedRouting }

pub enum ExtWalk<'a> {
    Done { next_header: u8, payload: &'a [u8] },
    Fragment { next_header: u8, offset: usize, more: bool, id: u32, payload: &'a [u8] },
}

fn is_skip_header(next: u8) -> bool {
    matches!(next, NH_HOP_BY_HOP | NH_DEST_OPTS | NH_ROUTING)
}

/// Walk IPv6 extension headers until an upper-layer payload or Fragment header. # C: O(headers)
pub fn walk(mut next: u8, mut payload: &[u8]) -> Result<ExtWalk<'_>, Ipv6ExtError> {
    while is_skip_header(next) {
        if payload.len() < 2 { return Err(Ipv6ExtError::Short); }
        if next == NH_ROUTING && payload.len() >= 4 && payload[3] != 0 {
            return Err(Ipv6ExtError::UnsupportedRouting);
        }
        let hdr_len = (payload[1] as usize + 1) * 8;
        if hdr_len > payload.len() { return Err(Ipv6ExtError::BadLen); }
        next = payload[0];
        payload = &payload[hdr_len..];
    }
    if next == NH_FRAGMENT {
        if payload.len() < 8 { return Err(Ipv6ExtError::Short); }
        let frag = u16::from_be_bytes([payload[2], payload[3]]);
        let offset = (((frag >> 3) & 0x1fff) as usize) * 8;
        let more = (frag & 1) != 0;
        let id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        return Ok(ExtWalk::Fragment { next_header: payload[0], offset, more, id, payload: &payload[8..] });
    }
    Ok(ExtWalk::Done { next_header: next, payload })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_hbh_routing_and_destination_options() {
        let udp = [1u8, 2, 3, 4];
        let mut p = [0u8; 28];
        p[0] = NH_ROUTING;
        p[8] = NH_DEST_OPTS;
        p[10] = 4;
        p[11] = 0;
        p[16] = 17;
        p[24..].copy_from_slice(&udp);
        match walk(NH_HOP_BY_HOP, &p).unwrap() {
            ExtWalk::Done { next_header, payload } => {
                assert_eq!(next_header, 17);
                assert_eq!(payload, &udp);
            }
            _ => panic!("expected upper-layer payload"),
        }
    }

    #[test]
    fn returns_fragment_metadata() {
        let mut p = [0u8; 20];
        p[0] = NH_FRAGMENT;
        p[8] = 17;
        p[10..12].copy_from_slice(&((2u16 << 3) | 1).to_be_bytes());
        p[12..16].copy_from_slice(&0x1122_3344u32.to_be_bytes());
        match walk(NH_DEST_OPTS, &p).unwrap() {
            ExtWalk::Fragment { next_header, offset, more, id, payload } => {
                assert_eq!(next_header, 17);
                assert_eq!(offset, 16);
                assert!(more);
                assert_eq!(id, 0x1122_3344);
                assert_eq!(payload.len(), 4);
            }
            _ => panic!("expected fragment"),
        }
    }
}
