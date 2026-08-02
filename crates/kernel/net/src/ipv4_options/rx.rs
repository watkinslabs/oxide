// IPv4 header option area on receive: the pass a locally delivered header
// runs before anything sees it, and the reply area a receiver echoes back.
// No target gate — every decision here is hosted-testable.

use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::addr::Ipv4Addr;
use super::area::{self, AddrClass, Compiled};
use super::emit;
use super::uapi::*;

/// `ip_rcv_options`: compile a received header's option area, then pay what
/// this host owes it — its address in the record-route slot, the arrival stamp
/// in the timestamp slot, or the overflow counter when neither has room.
/// `spec_dst` is the address this host answered the packet on.
///
/// An area this rejects is a header error: the packet is dropped rather than
/// delivered with an option area nothing can echo. # C: O(optlen + addresses)
pub fn received(area: &[u8], class: &dyn AddrClass, spec_dst: Ipv4Addr, stamp_ms: u32)
    -> Result<Compiled, Errno>
{
    let mut c = area::build_packet(area, class)?;
    let mut data = core::mem::take(&mut c.data);
    emit::fill_slots(&mut data, &c, spec_dst, stamp_ms);
    c.data = data;
    Ok(c)
}

/// `fib_compute_spec_dst`: the address this host answered the packet on. A
/// unicast destination is that destination; a broadcast or multicast one
/// names no single host, so the receiving interface's own address answers for
/// it. # C: O(addresses)
pub fn spec_dst(net_ns: u64, iface: crate::addr::NetIfaceId, dst: Ipv4Addr) -> Ipv4Addr {
    if !dst.is_multicast() && !dst.is_broadcast() { return dst; }
    crate::iface_addr::primary(net_ns, iface).map_or(dst, |(addr, _)| addr)
}

/// The whole receive-side pass for one delivered header: the address this host
/// answered on, then [`received`] against that namespace's own addresses.
/// # C: O(optlen + addresses)
pub fn delivered(net_ns: u64, iface: crate::addr::NetIfaceId, dst: Ipv4Addr, area: &[u8])
    -> Result<Compiled, Errno>
{
    let class = super::compile::RemoteUnicast { net_ns };
    received(area, &class, spec_dst(net_ns, iface, dst), emit::timestamp())
}

/// `__ip_options_echo`: the option area a reply to this packet carries. The
/// record-route and timestamp options ride back as received with their
/// pointers stepped over the slot this host just filled, the source route is
/// reversed so the reply retraces the path, and a commercial-security option
/// is copied verbatim. Every other kind is dropped, which is what keeps a
/// stream identifier or an unassigned option from being reflected at its
/// sender. # C: O(optlen)
pub fn echo(sopt: &Compiled, saddr: Ipv4Addr) -> Result<Compiled, Errno> {
    let src = &sopt.data;
    let mut d = Compiled::default();
    if src.is_empty() { return Ok(d); }
    if let Some(at) = sopt.rr {
        let optlen = opt_len(src, at)?;
        let mut soffset = src[at + 2] as usize;
        d.rr = Some(d.data.len());
        let base = d.data.len();
        d.data.extend_from_slice(&src[at..at + optlen]);
        if sopt.rr_needaddr && soffset <= optlen {
            if soffset + 3 > optlen { return Err(Errno::Einval); }
            soffset += 4;
            d.data[base + 2] = soffset as u8;
            d.rr_needaddr = true;
        }
    }
    if let Some(at) = sopt.ts {
        let optlen = opt_len(src, at)?;
        let mut soffset = src[at + 2] as usize;
        d.ts = Some(d.data.len());
        let base = d.data.len();
        d.data.extend_from_slice(&src[at..at + optlen]);
        if soffset <= optlen {
            if sopt.ts_needaddr {
                if soffset + 3 > optlen { return Err(Errno::Einval); }
                d.ts_needaddr = true;
                soffset += 4;
            }
            if sopt.ts_needtime {
                if soffset + 3 > optlen { return Err(Errno::Einval); }
                if d.data[base + 3] & 0xf != IPOPT_TS_PRESPEC {
                    d.ts_needtime = true;
                    soffset += 4;
                } else {
                    // A prespecified list only owes a stamp at a slot naming
                    // an address this host does not answer for, so whether the
                    // reply still owes one is decided slot by slot.
                    d.ts_needtime = false;
                    if soffset + 7 <= optlen {
                        d.ts_needtime = true;
                        soffset += 8;
                    }
                }
            }
            d.data[base + 2] = soffset as u8;
        }
    }
    if let Some(at) = sopt.srr { echo_srr(src, at, saddr, sopt.is_strictroute, &mut d)?; }
    if let Some(at) = sopt.cipso {
        let optlen = opt_len(src, at)?;
        d.cipso = Some(d.data.len());
        d.data.extend_from_slice(&src[at..at + optlen]);
    }
    while d.data.len() & 3 != 0 { d.data.push(IPOPT_END); }
    Ok(d)
}

/// The reversed source route a reply carries: the hops the packet already
/// traversed, latest first, with the hop that forwarded it lifted out as the
/// reply's first destination. A route whose last recorded hop is the sender
/// itself drops that slot, so the reply does not name the sender twice.
///
/// The reply's declared length covers exactly the hops it carries. A route
/// whose lowest slot is not the sender leaves a trailing slot unaccounted for
/// upstream; naming bytes the reply never wrote is not reproduced here.
/// # C: O(hops)
fn echo_srr(src: &[u8], at: usize, saddr: Ipv4Addr, strict: bool, d: &mut Compiled)
    -> Result<(), Errno>
{
    let optlen = opt_len(src, at)?;
    let mut soffset = src[at + 2] as usize;
    if soffset > optlen { soffset = optlen + 1; }
    if soffset < 4 { return Ok(()); }
    soffset -= 4;
    let mut hops: Vec<[u8; 4]> = Vec::new();
    let mut faddr = [0u8; 4];
    if soffset > 3 {
        if at + soffset + 3 > src.len() { return Err(Errno::Einval); }
        faddr.copy_from_slice(&src[at + soffset - 1..at + soffset + 3]);
        soffset -= 4;
        while soffset > 3 {
            if at + soffset + 3 > src.len() { return Err(Errno::Einval); }
            let mut hop = [0u8; 4];
            hop.copy_from_slice(&src[at + soffset - 1..at + soffset + 3]);
            hops.push(hop);
            soffset -= 4;
        }
        // A route whose lowest slot already holds the sender's address would
        // send the reply to its origin twice, so that slot is dropped.
        if at + soffset + 7 <= src.len()
            && src[at + soffset + 3..at + soffset + 7] == saddr.octets()
        {
            hops.pop();
        }
    }
    if hops.is_empty() { return Ok(()); }
    let doffset = 4 * hops.len();
    d.faddr = faddr;
    d.srr = Some(d.data.len());
    d.is_strictroute = strict;
    d.data.push(src[at]);
    d.data.push((doffset + 3) as u8);
    d.data.push(4);
    for hop in &hops { d.data.extend_from_slice(hop); }
    Ok(())
}

/// One option's declared length, refused when it does not fit the area.
/// # C: O(1)
fn opt_len(src: &[u8], at: usize) -> Result<usize, Errno> {
    let optlen = *src.get(at + 1).ok_or(Errno::Einval)? as usize;
    if optlen < 3 || at + optlen > src.len() { return Err(Errno::Einval); }
    Ok(optlen)
}
