// Sticky IPv6 extension headers: the shape screen `setsockopt` runs before a
// header is attached to the socket, and the routing header's extra check.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::state::Sticky;
use super::uapi::*;
use crate::sock_opts::sol_socket::OptCaps;

/// The slot one option number names. # C: O(1)
pub fn slot(optname: u64) -> Option<Sticky> {
    Some(match optname {
        IPV6_HOPOPTS => Sticky::HopOpts,
        IPV6_RTHDRDSTOPTS => Sticky::RthdrDstOpts,
        IPV6_RTHDR => Sticky::Rthdr,
        IPV6_DSTOPTS => Sticky::DstOpts,
        _ => return None,
    })
}

/// `ipv6_set_opt_hdr`: hop-by-hop and destination options are a privileged
/// construction, a zero-length area removes whatever the slot held, and the
/// declared header length may not exceed the bytes the caller supplied.
/// # C: O(len)
pub fn admit(optname: u64, bytes: &[u8], caps: OptCaps)
    -> Result<Option<Vec<u8>>, Errno>
{
    if optname != IPV6_RTHDR && !caps.net_raw { return Err(Errno::Eperm); }
    if bytes.is_empty() { return Ok(None); }
    if bytes.len() < IPV6_OPT_HDR_SIZE || bytes.len() & 7 != 0
        || bytes.len() > IPV6_OPT_MAX
    {
        return Err(Errno::Einval);
    }
    // `hdrlen` counts eight-byte units beyond the first, so a header claiming
    // more than the caller supplied is refused rather than read past.
    if declared_len(bytes) > bytes.len() { return Err(Errno::Einval); }
    if optname == IPV6_RTHDR { admit_rthdr(bytes)?; }
    Ok(Some(Vec::from(bytes)))
}

/// `ipv6_optlen`. # C: O(1)
pub fn declared_len(bytes: &[u8]) -> usize { (bytes[1] as usize + 1) << 3 }

/// A sticky routing header is accepted only in the segment-routing form: every
/// other type, including the deprecated source route, is refused. # C: O(len)
fn admit_rthdr(bytes: &[u8]) -> Result<(), Errno> {
    // `struct ipv6_rt_hdr`: next header, header length, routing type,
    // segments left.
    if bytes[2] != IPV6_SRCRT_TYPE_4 { return Err(Errno::Einval); }
    if validate_srh(bytes) { Ok(()) } else { Err(Errno::Einval) }
}

/// `seg6_validate_srh` in its non-reduced form: the declared length must match
/// the area exactly, the segment list must fit, and the trailing
/// type-length-value chain must tile the remainder. # C: O(len)
pub fn validate_srh(b: &[u8]) -> bool {
    const SRH_SIZE: usize = 8;
    if b.len() < SRH_SIZE { return false; }
    if b[2] != IPV6_SRCRT_TYPE_4 { return false; }
    let (hdrlen, segments_left, first_segment) = (b[1] as usize, b[3] as usize, b[4] as usize);
    if (hdrlen + 1) << 3 != b.len() { return false; }
    if segments_left > first_segment { return false; }
    let max_last_entry = (hdrlen / 2).wrapping_sub(1);
    if hdrlen < 2 || first_segment > max_last_entry { return false; }
    if segments_left > first_segment + 1 { return false; }
    let mut at = SRH_SIZE + ((first_segment + 1) << 4);
    if at > b.len() { return false; }
    while at < b.len() {
        // `struct sr6_tlv`: a type byte then a length byte.
        if b.len() - at < 2 { return false; }
        let tlv_len = 2 + b[at + 1] as usize;
        if b.len() - at < tlv_len { return false; }
        at += tlv_len;
    }
    true
}
