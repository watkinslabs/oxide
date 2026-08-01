// `UDP_SEGMENT` transmit planning: the rejection ladder a segmented send runs
// before any packet is built, and the resulting segment split.

use crate::NetError;

use super::uapi::{UDP_MAX_SEGMENTS, UDP4_SEGMENT_HDR_LEN, UDP6_SEGMENT_HDR_LEN};

/// How one oversized payload is cut into wire datagrams.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentPlan { pub seg_size: usize, pub count: usize }

/// Decide whether a send segments, and reject the combinations that cannot.
///
/// The ladder runs whenever a segmentation size is set, even when the payload
/// already fits one segment, so an unsendable configuration is reported at the
/// first send rather than silently on a later larger one. Order is fixed:
/// a segment that cannot fit the path comes first, then a payload needing more
/// segments than one send may carry, then the checksum-suppressed combination
/// that has no way to describe per-segment checksums.
///
/// `Ok(None)` means "send this payload as one ordinary datagram".
/// # C: O(1)
pub fn plan(datalen: usize, gso_size: usize, hdr_len: usize, path_mtu: usize, no_check_tx: bool)
    -> Result<Option<SegmentPlan>, NetError>
{
    if gso_size == 0 { return Ok(None); }
    if hdr_len + core::cmp::min(datalen, gso_size) > path_mtu { return Err(NetError::Emsgsize); }
    if datalen > gso_size.saturating_mul(UDP_MAX_SEGMENTS) { return Err(NetError::Einval); }
    if no_check_tx { return Err(NetError::Einval); }
    if datalen <= gso_size { return Ok(None); }
    Ok(Some(SegmentPlan { seg_size: gso_size, count: datalen.div_ceil(gso_size) }))
}

/// IPv4 plan: the segment must fit the path MTU behind an IPv4 + UDP header.
/// # C: O(1)
pub fn plan_v4(datalen: usize, gso_size: usize, path_mtu: usize, no_check_tx: bool)
    -> Result<Option<SegmentPlan>, NetError>
{ plan(datalen, gso_size, UDP4_SEGMENT_HDR_LEN, path_mtu, no_check_tx) }

/// IPv6 plan: same ladder behind an IPv6 + UDP header. # C: O(1)
pub fn plan_v6(datalen: usize, gso_size: usize, path_mtu: usize, no_check_tx: bool)
    -> Result<Option<SegmentPlan>, NetError>
{ plan(datalen, gso_size, UDP6_SEGMENT_HDR_LEN, path_mtu, no_check_tx) }
