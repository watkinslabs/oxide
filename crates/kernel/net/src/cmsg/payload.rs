// Wire layout of every non-scalar receive ancillary message.

use alloc::vec::Vec;

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

/// IPv4 option kinds the echo pass recognizes.
const IPOPT_END: u8 = 0;
const IPOPT_NOOP: u8 = 1;
const IPOPT_RR: u8 = 7;
const IPOPT_TIMESTAMP: u8 = 68;
const IPOPT_LSRR: u8 = 131;
const IPOPT_SSRR: u8 = 137;

/// `ip_options_echo`: the option area a reply to this datagram would carry —
/// the record-route and timestamp options as received, and the source route
/// REVERSED so the reply retraces the path. Every other option kind is
/// dropped, which is what keeps a security or stream-identifier option from
/// being reflected back at its sender.
///
/// This stack fills no record-route or timestamp slot on receive, since it is
/// not a router, so the inverse pass that a forwarding kernel would run over
/// the echoed copy has nothing to retract. # C: O(optlen)
pub fn echo_options(area: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut rr = None;
    let mut ts = None;
    let mut srr = None;
    while at < area.len() {
        match area[at] {
            IPOPT_END => break,
            IPOPT_NOOP => { at += 1; continue; }
            _ => {}
        }
        if area.len() - at < 2 { return Vec::new(); }
        let optlen = area[at + 1] as usize;
        if optlen < 2 || optlen > area.len() - at { return Vec::new(); }
        match area[at] {
            IPOPT_RR if rr.is_none() => rr = Some(at..at + optlen),
            IPOPT_TIMESTAMP if ts.is_none() => ts = Some(at..at + optlen),
            IPOPT_LSRR | IPOPT_SSRR if srr.is_none() => srr = Some(at..at + optlen),
            _ => {}
        }
        at += optlen;
    }
    if let Some(range) = rr { out.extend_from_slice(&area[range]); }
    if let Some(range) = ts { out.extend_from_slice(&area[range]); }
    if let Some(range) = srr { reverse_source_route(&area[range], &mut out); }
    // The area a reply carries is padded to a four-byte multiple like any
    // other header option area.
    while out.len() & 3 != 0 { out.push(IPOPT_END); }
    out
}

/// Rebuild a source route in the opposite direction: the hops the datagram
/// already traversed, latest first. A route with no traversed hop echoes
/// nothing at all. # C: O(hops)
fn reverse_source_route(opt: &[u8], out: &mut Vec<u8>) {
    let optlen = opt.len();
    if optlen < 7 { return; }
    // The pointer names the next unused slot, so everything below it has been
    // visited; the slot immediately below it is the hop that forwarded here.
    let mut soffset = opt[2] as usize;
    if soffset > optlen { soffset = optlen + 1; }
    if soffset < 4 { return; }
    soffset -= 4;
    if soffset <= 3 { return; }
    let mut hops = Vec::new();
    let mut at = soffset;
    while at > 3 {
        if at + 3 > optlen { return; }
        hops.push(&opt[at - 1..at + 3]);
        at -= 4;
    }
    // The first hop of the reply is the last hop of the request, which the
    // caller receives separately rather than inside the list.
    let Some((_first, rest)) = hops.split_first() else { return; };
    if rest.is_empty() { return; }
    let doffset = 4 * rest.len();
    out.push(opt[0]);
    out.push((doffset + 3) as u8);
    out.push(4);
    for hop in rest { out.extend_from_slice(hop); }
}
