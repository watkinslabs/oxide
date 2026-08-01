// EDID command wire format and fetch policy (virtio 1.2 §5.7.6.8).
//
// The device carries the display's EDID as an opaque VESA blob; nothing here
// interprets it. Decoding belongs to the DRM EDID owner.

extern crate alloc;

use alloc::vec::Vec;

use crate::wire::{
    read_u32_le, write_u32_le, Error, KResult, VIRTIO_GPU_CMD_GET_EDID, VIRTIO_GPU_F_EDID,
    VIRTIO_GPU_RESP_OK_EDID,
};

/// `struct virtio_gpu_get_edid`: ctrl header, then the scanout and its padding.
pub const GET_EDID_HDR_LEN: usize = 24;
pub const GET_EDID_SCANOUT_OFF: usize = GET_EDID_HDR_LEN;
pub const GET_EDID_PADDING_OFF: usize = GET_EDID_SCANOUT_OFF + 4;
pub const GET_EDID_REQ_LEN: usize = GET_EDID_PADDING_OFF + 4;

/// `struct virtio_gpu_resp_edid`: ctrl header, valid byte count, padding, blob.
pub const RESP_EDID_SIZE_OFF: usize = GET_EDID_HDR_LEN;
pub const RESP_EDID_PADDING_OFF: usize = RESP_EDID_SIZE_OFF + 4;
pub const RESP_EDID_DATA_OFF: usize = RESP_EDID_PADDING_OFF + 4;
/// Bytes the response reserves for the blob, whatever `size` reports.
pub const EDID_MAX_BYTES: usize = 1024;
pub const RESP_EDID_LEN: usize = RESP_EDID_DATA_OFF + EDID_MAX_BYTES;

/// The scanout whose display backs the console and the primary connector.
pub const PRIMARY_SCANOUT: u32 = 0;

/// Whether to issue `CMD_GET_EDID`. The specification says a driver that
/// negotiated the EDID feature should fetch the display's EDID; a driver that
/// did not must not send the command at all, since the device need not
/// implement it. # C: O(1)
pub fn should_fetch(features_negotiated: u64) -> bool {
    features_negotiated & (1u64 << VIRTIO_GPU_F_EDID) != 0
}

/// Encode `CMD_GET_EDID` for a given scanout. Writes `GET_EDID_REQ_LEN` bytes.
/// # C: O(1)
pub fn encode_get_edid(buf: &mut [u8], scanout: u32) -> usize {
    if buf.len() < GET_EDID_REQ_LEN { return 0; }
    for b in &mut buf[..GET_EDID_REQ_LEN] { *b = 0; }
    write_u32_le(buf, 0, VIRTIO_GPU_CMD_GET_EDID);
    write_u32_le(buf, GET_EDID_SCANOUT_OFF, scanout);
    write_u32_le(buf, GET_EDID_PADDING_OFF, 0);
    GET_EDID_REQ_LEN
}

/// Valid bytes of a `CMD_GET_EDID` response.
///
/// `size` counts the bytes the device filled; the remainder of the fixed
/// 1024-byte field carries no meaning, so it is never handed on. A `size`
/// beyond the field is clamped rather than trusted. # C: O(1)
pub fn parse_edid_bytes(resp: &[u8]) -> KResult<&[u8]> {
    if resp.len() < RESP_EDID_LEN { return Err(Error::Inval); }
    let ty = read_u32_le(resp, 0);
    if ty != VIRTIO_GPU_RESP_OK_EDID { return Err(Error::BadResp(ty)); }
    let size = (read_u32_le(resp, RESP_EDID_SIZE_OFF) as usize).min(EDID_MAX_BYTES);
    Ok(&resp[RESP_EDID_DATA_OFF..RESP_EDID_DATA_OFF + size])
}

/// Keep a fetched blob only when it decodes as an EDID base block. A device
/// that reports a size but fills the field with nothing usable would otherwise
/// publish a connector EDID that userspace cannot parse, and an allocation
/// failure here is the same non-event as a display without an EDID.
/// # C: O(blob bytes)
pub fn accept_edid(bytes: &[u8]) -> Option<Vec<u8>> {
    if !drm::edid::is_valid(bytes) { return None; }
    let mut out = Vec::new();
    if out.try_reserve_exact(bytes.len()).is_err() { return None; }
    out.extend_from_slice(bytes);
    Some(out)
}

#[cfg(test)]
mod tests;
