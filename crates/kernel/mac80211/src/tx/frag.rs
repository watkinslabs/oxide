// Fragmentation.
//
// A frame is split so that each piece, HEADER AND CIPHER OVERHEAD INCLUDED,
// fits under the threshold. Splitting the payload to the threshold and then
// adding the header produces fragments over it, which is the mistake that
// makes a fragmentation threshold appear not to work.

extern crate alloc;

use alloc::vec::Vec;

use crate::limits;

/// How one frame is split. Each entry is a payload slice range and whether
/// another follows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fragment {
    pub start: usize,
    pub end: usize,
    pub number: u16,
    pub more: bool,
}

/// Whether a frame of this size needs splitting at all. # C: O(1)
pub fn needed(threshold: u32, hdr_len: usize, overhead: usize, payload_len: usize) -> bool {
    if threshold >= limits::FRAG_THRESHOLD_OFF { return false; }
    (hdr_len + overhead + payload_len) as u32 > threshold
}

/// Split a payload. `hdr_len` is the 802.11 header each fragment repeats and
/// `overhead` is what the cipher adds to each. A threshold too small to hold
/// even one payload byte per fragment yields a single unsplit fragment: an
/// endless list of empty fragments is worse than a frame over the threshold.
/// # C: O(fragments)
pub fn split(threshold: u32, hdr_len: usize, overhead: usize, payload_len: usize)
    -> Vec<Fragment>
{
    if !needed(threshold, hdr_len, overhead, payload_len) {
        return alloc::vec![Fragment { start: 0, end: payload_len, number: 0, more: false }];
    }
    let per = (threshold as usize).saturating_sub(hdr_len + overhead);
    if per == 0 {
        return alloc::vec![Fragment { start: 0, end: payload_len, number: 0, more: false }];
    }
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut number = 0u16;
    while at < payload_len {
        let end = (at + per).min(payload_len);
        // The fragment number field is four bits wide; a payload that would
        // need more pieces than that goes out as one oversized last fragment
        // rather than as pieces the receiver cannot order.
        let last = end >= payload_len || number as usize + 1 >= limits::MAX_FRAGMENTS;
        let end = if last { payload_len } else { end };
        out.push(Fragment { start: at, end, number, more: !last });
        at = end;
        number += 1;
        if last { break; }
    }
    out
}
