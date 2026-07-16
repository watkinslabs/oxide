const PACKET_MREQ_ADDRESS_OFFSET: usize = 8;
const PACKET_MAX_ADDR_LEN: usize = 32;
pub(super) const PACKET_MREQ_SIZE: usize = 16;
pub(super) const PACKET_MREQ_MAX_SIZE: usize =
    PACKET_MREQ_ADDRESS_OFFSET + PACKET_MAX_ADDR_LEN;

/// Parse an exact native Linux packet boolean. # C: O(1)
pub(super) fn parse_packet_bool(bytes: &[u8], optlen: usize) -> Option<bool> {
    if optlen != core::mem::size_of::<i32>() || bytes.len() != optlen { return None; }
    match i32::from_ne_bytes(bytes.try_into().ok()?) {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

/// Parse Linux's minimum-four-byte packet flag convention. # C: O(1)
pub(super) fn parse_packet_flag(bytes: &[u8], optlen: usize) -> Option<bool> {
    if optlen < core::mem::size_of::<i32>() || bytes.len() != core::mem::size_of::<i32>() {
        return None;
    }
    Some(i32::from_ne_bytes(bytes.try_into().ok()?) != 0)
}

/// Parse Linux's native packet membership request. # C: O(address length)
pub(super) fn parse_packet_mreq(bytes: &[u8], optlen: usize)
    -> Option<net::sock::PacketMembershipRequest> {
    if optlen < PACKET_MREQ_SIZE || bytes.len() < PACKET_MREQ_SIZE { return None; }
    let ifindex = i32::from_ne_bytes(bytes[..4].try_into().ok()?) as u32;
    let kind = u16::from_ne_bytes(bytes[4..6].try_into().ok()?);
    let address_len = u16::from_ne_bytes(bytes[6..8].try_into().ok()?) as usize;
    if optlen < PACKET_MREQ_ADDRESS_OFFSET.saturating_add(address_len) { return None; }
    let mut address = [0u8; PACKET_MAX_ADDR_LEN];
    let available = bytes.len().saturating_sub(PACKET_MREQ_ADDRESS_OFFSET);
    let take = core::cmp::min(address_len, available);
    address[..take].copy_from_slice(
        &bytes[PACKET_MREQ_ADDRESS_OFFSET..PACKET_MREQ_ADDRESS_OFFSET + take]);
    Some(net::sock::PacketMembershipRequest {
        ifindex, kind,
        address: net::PacketLinkAddress {
            len: address_len.min(u8::MAX as usize) as u8, bytes: address,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(ifindex: i32, kind: u16, address: &[u8], optlen: usize) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec![0xa5; optlen.min(PACKET_MREQ_MAX_SIZE)];
        bytes[..4].copy_from_slice(&ifindex.to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes[6..8].copy_from_slice(&(address.len() as u16).to_ne_bytes());
        bytes[8..8 + address.len()].copy_from_slice(address);
        bytes
    }

    #[test]
    fn native_packet_mreq_fields_and_address_are_preserved() {
        let address = [0x02, 0x4f, 0x58, 0, 0, 7];
        let parsed = parse_packet_mreq(&request(17, 3, &address, 16), 16).unwrap();
        assert_eq!(parsed.ifindex, 17);
        assert_eq!(parsed.kind, 3);
        assert_eq!(parsed.address.len, address.len() as u8);
        assert_eq!(&parsed.address.bytes[..address.len()], &address);
    }

    #[test]
    fn short_fixed_header_is_rejected() {
        assert!(parse_packet_mreq(&[0; PACKET_MREQ_SIZE - 1], PACKET_MREQ_SIZE - 1).is_none());
    }

    #[test]
    fn address_length_must_fit_declared_optlen() {
        let mut bytes = request(2, 0, &[1, 2, 3, 4, 5, 6], 16);
        bytes[6..8].copy_from_slice(&9u16.to_ne_bytes());
        assert!(parse_packet_mreq(&bytes, 16).is_none());
    }

    #[test]
    fn extended_packet_mreq_is_capped_without_losing_native_fields() {
        let address = [0x11; PACKET_MAX_ADDR_LEN];
        let parsed = parse_packet_mreq(&request(-1, 0x1234, &address, 80), 80).unwrap();
        assert_eq!(parsed.ifindex, u32::MAX);
        assert_eq!(parsed.kind, 0x1234);
        assert_eq!(parsed.address.len, PACKET_MAX_ADDR_LEN as u8);
        assert_eq!(parsed.address.bytes, address);
    }

    #[test]
    fn packet_boolean_requires_exact_native_int_and_zero_or_one() {
        assert_eq!(parse_packet_bool(&0i32.to_ne_bytes(), 4), Some(false));
        assert_eq!(parse_packet_bool(&1i32.to_ne_bytes(), 4), Some(true));
        assert_eq!(parse_packet_bool(&2i32.to_ne_bytes(), 4), None);
        assert_eq!(parse_packet_bool(&(-1i32).to_ne_bytes(), 4), None);
        assert_eq!(parse_packet_bool(&[0; 3], 3), None);
        assert_eq!(parse_packet_bool(&[0; 8], 8), None);
    }

    #[test]
    fn packet_flags_accept_extended_lengths_and_any_nonzero_int() {
        assert_eq!(parse_packet_flag(&0i32.to_ne_bytes(), 4), Some(false));
        assert_eq!(parse_packet_flag(&(-1i32).to_ne_bytes(), 4), Some(true));
        assert_eq!(parse_packet_flag(&7i32.to_ne_bytes(), 32), Some(true));
        assert_eq!(parse_packet_flag(&[0; 3], 3), None);
    }
}
