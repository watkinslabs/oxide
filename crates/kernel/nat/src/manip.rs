//! Rewriting the packet. Every field changed here participates in a checksum,
//! and every checksum is updated incrementally — recomputing from scratch is
//! both slower and wrong for a partially-checksummed packet.

use conntrack::tuple::{InetAddr, Tuple};
use conntrack::uapi::{IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_SCTP, IPPROTO_TCP,
                      IPPROTO_UDP, IPPROTO_UDPLITE, NFPROTO_IPV6};

use crate::uapi::{NF_NAT_MANIP_SRC};

/// Ones-complement fold of a 32-bit accumulator. # C: O(1)
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

/// Update a ones-complement checksum for a 16-bit field change. Passing the
/// old and new values rather than rescanning keeps the update O(1) and
/// correct for headers the kernel never sees in full.
/// # C: O(1)
pub fn csum_replace2(check: u16, old: u16, new: u16) -> u16 {
    let sum = (!check) as u32 + (!old) as u32 + new as u32;
    fold(sum)
}

/// Same, for a 32-bit field. # C: O(1)
pub fn csum_replace4(check: u16, old: u32, new: u32) -> u16 {
    let sum = (!check) as u32
        + (!(old >> 16) as u16) as u32 + (!(old & 0xffff) as u16) as u32
        + (new >> 16) + (new & 0xffff);
    fold(sum)
}

/// Update a checksum for an address change of any width. # C: O(addr len)
pub fn csum_replace_addr(mut check: u16, old: &InetAddr, new: &InetAddr, len: usize) -> u16 {
    let mut i = 0;
    while i + 1 < len {
        let o = u16::from_be_bytes([old.0[i], old.0[i + 1]]);
        let n = u16::from_be_bytes([new.0[i], new.0[i + 1]]);
        if o != n { check = csum_replace2(check, o, n); }
        i += 2;
    }
    check
}

/// A UDP checksum of zero means "not computed" and must stay meaningful: if
/// an update lands on zero it is written as all-ones instead, which is the
/// same value in ones-complement arithmetic but is not the "absent" marker.
/// # C: O(1)
pub fn udp_csum_fixup(check: u16) -> u16 { if check == 0 { 0xffff } else { check } }

/// Where a protocol keeps the fields NAT rewrites, as byte offsets from the
/// start of its header.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct L4Layout {
    pub src_port: Option<usize>,
    pub dst_port: Option<usize>,
    /// ICMP identifier.
    pub id: Option<usize>,
    /// Checksum field, when the protocol has one NAT must maintain.
    pub checksum: Option<usize>,
    /// Whether a zero checksum means "absent".
    pub zero_means_absent: bool,
    /// Whether the checksum covers the L3 addresses via a pseudo-header.
    pub pseudo_header: bool,
}

/// Field layout for one L4 protocol. `None` means NAT has nothing to rewrite
/// inside the L4 header. # C: O(1)
pub fn l4_layout(protonum: u8) -> Option<L4Layout> {
    match protonum {
        IPPROTO_TCP => Some(L4Layout { src_port: Some(0), dst_port: Some(2), id: None,
            checksum: Some(16), zero_means_absent: false, pseudo_header: true }),
        IPPROTO_UDP | IPPROTO_UDPLITE => Some(L4Layout { src_port: Some(0), dst_port: Some(2),
            id: None, checksum: Some(6), zero_means_absent: true, pseudo_header: true }),
        IPPROTO_ICMP => Some(L4Layout { src_port: None, dst_port: None, id: Some(4),
            checksum: Some(2), zero_means_absent: false, pseudo_header: false }),
        IPPROTO_ICMPV6 => Some(L4Layout { src_port: None, dst_port: None, id: Some(4),
            checksum: Some(2), zero_means_absent: false, pseudo_header: true }),
        // The SCTP checksum is a CRC over the whole packet, not an incremental
        // ones-complement sum, so an incremental update would corrupt it.
        IPPROTO_SCTP => Some(L4Layout { src_port: Some(0), dst_port: Some(2), id: None,
            checksum: None, zero_means_absent: false, pseudo_header: false }),
        _ => None,
    }
}

/// Why a rewrite could not be applied.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ManipError {
    /// The buffer is shorter than the headers it claims.
    Truncated,
    /// The protocol has no field NAT knows how to rewrite.
    Unsupported,
}

/// Rewrite an IPv4 packet in place so it presents `target`. `l4_off` is the
/// offset of the L4 header; the IPv4 header starts at zero.
/// # C: O(addr len)
pub fn manip_ipv4(buf: &mut [u8], l4_off: usize, target: &Tuple, manip: u8)
    -> Result<(), ManipError>
{
    const IPV4_MIN_HDR: usize = 20;
    const IPV4_CHECK_OFF: usize = 10;
    const IPV4_SADDR_OFF: usize = 12;
    const IPV4_DADDR_OFF: usize = 16;
    if buf.len() < IPV4_MIN_HDR || buf.len() < l4_off { return Err(ManipError::Truncated); }

    let (new_addr, addr_off) = if manip == NF_NAT_MANIP_SRC {
        (target.src.addr, IPV4_SADDR_OFF)
    } else {
        (target.dst.addr, IPV4_DADDR_OFF)
    };
    let old_word = u32::from_be_bytes([buf[addr_off], buf[addr_off + 1],
                                       buf[addr_off + 2], buf[addr_off + 3]]);
    let new_word = new_addr.as_v4_u32();

    manip_l4(buf, l4_off, target, manip, old_word, new_word, false)?;

    let check = u16::from_be_bytes([buf[IPV4_CHECK_OFF], buf[IPV4_CHECK_OFF + 1]]);
    let check = csum_replace4(check, old_word, new_word);
    buf[IPV4_CHECK_OFF..IPV4_CHECK_OFF + 2].copy_from_slice(&check.to_be_bytes());
    buf[addr_off..addr_off + 4].copy_from_slice(&new_word.to_be_bytes());
    Ok(())
}

/// Rewrite an IPv6 packet in place. IPv6 has no header checksum, so only the
/// L4 pseudo-header sums need fixing up.
/// # C: O(addr len)
pub fn manip_ipv6(buf: &mut [u8], l4_off: usize, target: &Tuple, manip: u8)
    -> Result<(), ManipError>
{
    const IPV6_MIN_HDR: usize = 40;
    const IPV6_SADDR_OFF: usize = 8;
    const IPV6_DADDR_OFF: usize = 24;
    if buf.len() < IPV6_MIN_HDR || buf.len() < l4_off { return Err(ManipError::Truncated); }

    let (new_addr, addr_off) = if manip == NF_NAT_MANIP_SRC {
        (target.src.addr, IPV6_SADDR_OFF)
    } else {
        (target.dst.addr, IPV6_DADDR_OFF)
    };
    let mut old_addr = [0u8; 16];
    old_addr.copy_from_slice(&buf[addr_off..addr_off + 16]);
    let old_addr = InetAddr(old_addr);

    manip_l4_v6(buf, l4_off, target, manip, &old_addr, &new_addr)?;
    buf[addr_off..addr_off + 16].copy_from_slice(&new_addr.0);
    Ok(())
}

fn write_port(buf: &mut [u8], at: usize, port: u16, csum_at: Option<usize>,
              zero_absent: bool)
{
    let old = u16::from_be_bytes([buf[at], buf[at + 1]]);
    if old == port { return; }
    buf[at..at + 2].copy_from_slice(&port.to_be_bytes());
    if let Some(c) = csum_at {
        let check = u16::from_be_bytes([buf[c], buf[c + 1]]);
        if !(zero_absent && check == 0) {
            let mut new = csum_replace2(check, old, port);
            if zero_absent { new = udp_csum_fixup(new); }
            buf[c..c + 2].copy_from_slice(&new.to_be_bytes());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn manip_l4(buf: &mut [u8], l4_off: usize, target: &Tuple, manip: u8,
            old_addr_word: u32, new_addr_word: u32, _v6: bool)
    -> Result<(), ManipError>
{
    let Some(l) = l4_layout(target.protonum) else { return Ok(()); };
    let csum_at = l.checksum.map(|c| l4_off + c);
    if let Some(c) = csum_at { if buf.len() < c + 2 { return Err(ManipError::Truncated); } }

    if let Some(id_off) = l.id {
        let at = l4_off + id_off;
        if buf.len() < at + 2 { return Err(ManipError::Truncated); }
        write_port(buf, at, target.src.proto.port, csum_at, l.zero_means_absent);
    } else {
        let off = if manip == NF_NAT_MANIP_SRC { l.src_port } else { l.dst_port };
        let port = if manip == NF_NAT_MANIP_SRC { target.src.proto.port }
                   else { target.dst.proto.port };
        if let Some(o) = off {
            let at = l4_off + o;
            if buf.len() < at + 2 { return Err(ManipError::Truncated); }
            write_port(buf, at, port, csum_at, l.zero_means_absent);
        }
    }

    if l.pseudo_header && old_addr_word != new_addr_word {
        if let Some(c) = csum_at {
            let check = u16::from_be_bytes([buf[c], buf[c + 1]]);
            if !(l.zero_means_absent && check == 0) {
                let mut new = csum_replace4(check, old_addr_word, new_addr_word);
                if l.zero_means_absent { new = udp_csum_fixup(new); }
                buf[c..c + 2].copy_from_slice(&new.to_be_bytes());
            }
        }
    }
    Ok(())
}

fn manip_l4_v6(buf: &mut [u8], l4_off: usize, target: &Tuple, manip: u8,
               old_addr: &InetAddr, new_addr: &InetAddr) -> Result<(), ManipError>
{
    let Some(l) = l4_layout(target.protonum) else { return Ok(()); };
    let csum_at = l.checksum.map(|c| l4_off + c);
    if let Some(c) = csum_at { if buf.len() < c + 2 { return Err(ManipError::Truncated); } }

    if let Some(id_off) = l.id {
        let at = l4_off + id_off;
        if buf.len() < at + 2 { return Err(ManipError::Truncated); }
        write_port(buf, at, target.src.proto.port, csum_at, l.zero_means_absent);
    } else {
        let off = if manip == NF_NAT_MANIP_SRC { l.src_port } else { l.dst_port };
        let port = if manip == NF_NAT_MANIP_SRC { target.src.proto.port }
                   else { target.dst.proto.port };
        if let Some(o) = off {
            let at = l4_off + o;
            if buf.len() < at + 2 { return Err(ManipError::Truncated); }
            write_port(buf, at, port, csum_at, l.zero_means_absent);
        }
    }

    if l.pseudo_header && old_addr != new_addr {
        if let Some(c) = csum_at {
            let check = u16::from_be_bytes([buf[c], buf[c + 1]]);
            if !(l.zero_means_absent && check == 0) {
                let mut new = csum_replace_addr(check, old_addr, new_addr, 16);
                if l.zero_means_absent { new = udp_csum_fixup(new); }
                buf[c..c + 2].copy_from_slice(&new.to_be_bytes());
            }
        }
    }
    Ok(())
}

/// Rewrite a packet of either family. # C: O(addr len)
pub fn manip_packet(buf: &mut [u8], l4_off: usize, target: &Tuple, manip: u8)
    -> Result<(), ManipError>
{
    if target.l3num == NFPROTO_IPV6 { manip_ipv6(buf, l4_off, target, manip) }
    else { manip_ipv4(buf, l4_off, target, manip) }
}
