// Probe-time EDID fetch. The specification asks a driver that negotiated the
// EDID feature to fetch the display's EDID; a device that declines, errors, or
// reports nothing simply leaves the connector without one, so no failure here
// may fail the probe. Every decision this path makes — whether to send the
// command, what the reply means, whether the blob is usable — is owned by the
// crate-level EDID module, which is hosted-testable.

use super::*;
use alloc::vec::Vec;

/// Fetch the primary scanout's EDID, or `None` when the feature was not
/// negotiated or the device produced no usable blob.
///
/// # SAFETY: caller owns the probe command frame and CTRLQ; both VAs are live,
/// the frame is at least `RESP_OFF + RESP_EDID_LEN` bytes, and no other
/// submission is in flight on this queue.
/// # C: O(spin-poll bound)
pub(super) unsafe fn fetch(
    features_negotiated: u64,
    cmd_buf_va: *mut u8, cmd_buf_pa: u64,
    ctrlq: virtio::VirtQueueResource, hhdm: u64,
) -> Option<Vec<u8>> {
    if !crate::should_fetch(features_negotiated) { return None; }
    // SAFETY: request and response areas both lie inside the probe command
    // frame the caller owns; the response is scrubbed so a stale reply from an
    // earlier command cannot be mistaken for this one.
    let req_len = unsafe {
        for k in 0..crate::GET_EDID_REQ_LEN {
            core::ptr::write_volatile(cmd_buf_va.add(k), 0);
        }
        for k in 0..crate::RESP_EDID_LEN {
            core::ptr::write_volatile(cmd_buf_va.add(probe::RESP_OFF as usize + k), 0);
        }
        let req = core::slice::from_raw_parts_mut(cmd_buf_va, crate::GET_EDID_REQ_LEN);
        crate::encode_get_edid(req, crate::PRIMARY_SCANOUT)
    };
    if req_len != crate::GET_EDID_REQ_LEN { return None; }
    // SAFETY: request encoded above at cmd_buf_pa; the response descriptor is
    // sized for the whole EDID reply inside the same probe frame.
    if !unsafe { probe::submit_raw(cmd_buf_pa, req_len, crate::RESP_EDID_LEN, ctrlq, hhdm) } {
        return None;
    }
    // SAFETY: the device wrote at most RESP_EDID_LEN bytes at RESP_OFF, which
    // lies inside the probe command frame the caller owns.
    let resp = unsafe {
        core::slice::from_raw_parts(
            cmd_buf_va.add(probe::RESP_OFF as usize) as *const u8, crate::RESP_EDID_LEN)
    };
    crate::accept_edid(crate::parse_edid_bytes(resp).ok()?)
}
