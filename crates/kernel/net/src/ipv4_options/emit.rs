// IPv4 header option emission: what a compiled option area becomes on the
// wire once the route decision is known. No target gate — the whole decision
// is hosted-testable.

use crate::addr::Ipv4Addr;
use crate::ipv4::{ip_checksum, IPV4_HDR_LEN, IPV4_VERSION};
use crate::sock_opts::sol_ip::options::Compiled;
use crate::sock_opts::sol_ip::uapi::{IPOPT_COPIED, IPOPT_END, IPOPT_NOOP};

/// Milliseconds in a day: the timestamp option counts from UTC midnight.
const TS_DAY_MS: u64 = 86_400_000;

/// The fixed part of the header the option area rides in front of. `dst` is
/// the FINAL destination — a compiled source route puts its first hop on the
/// wire and carries this address in the option's last slot.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Header {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub tos: u8,
    pub ttl: u8,
    pub id: u16,
    pub flags_frag: u16,
}

/// Header length one compiled option area asks for. # C: O(1)
pub fn header_len(opts: Option<&Compiled>) -> usize {
    IPV4_HDR_LEN + opts.map_or(0, Compiled::len)
}

/// The address the wire header carries: a compiled source route hands the
/// datagram to its first hop, so that is also the address the route lookup
/// must resolve. # C: O(1)
pub fn wire_dst(opts: Option<&Compiled>, dst: Ipv4Addr) -> Ipv4Addr {
    match opts {
        Some(c) if c.srr.is_some() => {
            Ipv4Addr::new(c.faddr[0], c.faddr[1], c.faddr[2], c.faddr[3])
        }
        _ => dst,
    }
}

/// Whether a compiled area demands the route reach its first hop directly.
/// # C: O(1)
pub fn is_strict_route(opts: Option<&Compiled>) -> bool {
    opts.is_some_and(|c| c.srr.is_some() && c.is_strictroute)
}

/// Milliseconds since UTC midnight, the timestamp option's unit. # C: O(1)
pub fn timestamp() -> u32 {
    ((vfs::inode_times::realtime_now_ns() / 1_000_000) % TS_DAY_MS) as u32
}

/// `ip_options_build`: record the real destination in the source route, the
/// outgoing interface address in the record-route and timestamp slots, and the
/// stamp itself. The fill pointers were already advanced by the compile pass,
/// so each slot sits behind the pointer it now names. # C: O(optlen)
pub fn fill(area: &mut [u8], c: &Compiled, src: Ipv4Addr, dst: Ipv4Addr, stamp_ms: u32) {
    if let Some(at) = c.srr {
        let optlen = area.get(at + 1).copied().unwrap_or(0) as usize;
        if optlen >= 4 { stamp(area, at + optlen - 4, dst.octets()); }
    }
    if c.rr_needaddr {
        if let Some(at) = c.rr {
            let ptr = area.get(at + 2).copied().unwrap_or(0) as usize;
            if ptr >= 5 { stamp(area, at + ptr - 5, src.octets()); }
        }
    }
    if let Some(at) = c.ts {
        let ptr = area.get(at + 2).copied().unwrap_or(0) as usize;
        if c.ts_needaddr && ptr >= 9 { stamp(area, at + ptr - 9, src.octets()); }
        if c.ts_needtime && ptr >= 5 { stamp(area, at + ptr - 5, stamp_ms.to_be_bytes()); }
    }
}

/// Write one four-byte option slot, ignoring an area too short to hold it.
/// # C: O(1)
fn stamp(area: &mut [u8], at: usize, value: [u8; 4]) {
    if let Some(slot) = area.get_mut(at..at + 4) { slot.copy_from_slice(&value); }
}

/// `ip_options_fragment`: an option whose kind lacks the copied bit rides only
/// the fragment carrying the first octet; every later fragment blanks it to
/// no-ops, keeping the header length identical across the set. # C: O(optlen)
pub fn fragment(area: &mut [u8]) {
    let mut at = 0usize;
    while at < area.len() {
        match area[at] {
            IPOPT_END => return,
            IPOPT_NOOP => { at += 1; continue; }
            _ => {}
        }
        if at + 1 >= area.len() { return; }
        let optlen = area[at + 1] as usize;
        if optlen < 2 || at + optlen > area.len() { return; }
        if area[at] & IPOPT_COPIED == 0 { area[at..at + optlen].fill(IPOPT_NOOP); }
        at += optlen;
    }
}

/// The compiled area every fragment after the first carries: the copied
/// options, and no record-route or timestamp slot left to fill. # C: O(optlen)
pub fn fragmented(c: &Compiled) -> Compiled {
    let mut out = c.clone();
    fragment(&mut out.data);
    out.rr = None;
    out.ts = None;
    out.rr_needaddr = false;
    out.ts_needaddr = false;
    out.ts_needtime = false;
    out
}

/// Serialize the header and its option area into `out`, whose length must be
/// exactly [`header_len`]. `payload_len` completes the total-length field.
/// # C: O(header)
pub fn write_header(out: &mut [u8], h: &Header, opts: Option<&Compiled>,
    payload_len: usize, stamp_ms: u32)
{
    if out.len() != header_len(opts) { return; }
    let total = (out.len() + payload_len) as u16;
    out[0] = (IPV4_VERSION << 4) | (out.len() / 4) as u8;
    out[1] = h.tos;
    out[2..4].copy_from_slice(&total.to_be_bytes());
    out[4..6].copy_from_slice(&h.id.to_be_bytes());
    out[6..8].copy_from_slice(&h.flags_frag.to_be_bytes());
    out[8] = h.ttl;
    out[9] = h.proto;
    out[10..12].fill(0);
    out[12..16].copy_from_slice(&h.src.octets());
    out[16..20].copy_from_slice(&wire_dst(opts, h.dst).octets());
    if let Some(c) = opts {
        out[IPV4_HDR_LEN..].copy_from_slice(&c.data);
        fill(&mut out[IPV4_HDR_LEN..], c, h.src, h.dst, stamp_ms);
    }
    let checksum = ip_checksum(out);
    out[10..12].copy_from_slice(&checksum.to_be_bytes());
}
