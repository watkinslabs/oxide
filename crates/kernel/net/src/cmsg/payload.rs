// Wire layout of every non-scalar receive ancillary message.


/// `struct in_pktinfo`: interface index, then the locally chosen source
/// address, then the datagram's destination. This stack answers both address
/// fields with the destination, which is the address a reply must come from.
/// # C: O(1)
pub fn in_pktinfo(addr: [u8; 4], ifindex: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(&(ifindex as i32).to_ne_bytes());
    out[4..8].copy_from_slice(&addr);
    out[8..12].copy_from_slice(&addr);
    out
}

/// `struct sockaddr_in`: family, port in network order, address, then the
/// eight padding bytes a caller may compare against zero. # C: O(1)
pub fn sockaddr_in(addr: [u8; 4], port: u16) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..2].copy_from_slice(&(crate::socket_args::AF_INET as u16).to_ne_bytes());
    out[2..4].copy_from_slice(&port.to_be_bytes());
    out[4..8].copy_from_slice(&addr);
    out
}

/// `struct in6_pktinfo`: the destination address, then the interface index.
/// # C: O(1)
pub fn in6_pktinfo(addr: [u8; 16], ifindex: u32) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[..16].copy_from_slice(&addr);
    out[16..20].copy_from_slice(&(ifindex as i32).to_ne_bytes());
    out
}

/// `struct sockaddr_in6`: family, port in network order, flow info, address,
/// then the scope identifier. The flow-info field is reported as zero, which
/// is what an original-destination answer carries. # C: O(1)
pub fn sockaddr_in6(addr: [u8; 16], port: u16, scope_id: u32) -> [u8; 28] {
    let mut out = [0u8; 28];
    out[..2].copy_from_slice(&(crate::socket_args::AF_INET6 as u16).to_ne_bytes());
    out[2..4].copy_from_slice(&port.to_be_bytes());
    out[8..24].copy_from_slice(&addr);
    out[24..28].copy_from_slice(&scope_id.to_ne_bytes());
    out
}
