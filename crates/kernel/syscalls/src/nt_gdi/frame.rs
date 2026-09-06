//! Convert the canonical GDI surface into an owned, bounded bridge frame.

use alloc::vec::Vec;
use syscall::nt_compositor::{self as wire, Error, Opcode, Record};

/// Snapshot XRGB pixels while the caller protects the GDI surface. The returned
/// record has no borrowed surface memory and is enqueued only after unlocking.
/// # C: O(width * height)
pub(crate) fn snapshot(hwnd: u32, sequence: u64, width: i32, height: i32, pixels: &[u32]) -> Result<Record, Error> {
    let width = u32::try_from(width).map_err(|_| Error::Payload)?;
    let height = u32::try_from(height).map_err(|_| Error::Payload)?;
    let stride = width.checked_mul(4).ok_or(Error::Overflow)?;
    let bytes = wire::pixel_len(width, height, stride, wire::PIXEL_BGRA8888)?;
    if pixels.len() != bytes / 4 { return Err(Error::Length); }
    let mut payload = Vec::new();
    payload.try_reserve_exact(16 + bytes).map_err(|_| Error::Allocation)?;
    for value in [width, height, stride, wire::PIXEL_BGRA8888] {
        payload.extend_from_slice(&value.to_le_bytes());
    }
    for pixel in pixels {
        payload.extend_from_slice(&(pixel | 0xff00_0000).to_le_bytes());
    }
    Record::new(Opcode::Frame, sequence, hwnd as u64, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_owns_pixels_and_sets_opaque_alpha() {
        let mut pixels = [0x0012_3456, 0x0078_9abc];
        let record = snapshot(7, 1, 2, 1, &pixels).unwrap();
        pixels.fill(0);
        assert_eq!(record.header.hwnd, 7);
        assert_eq!(&record.payload[16..], &[0x56, 0x34, 0x12, 0xff, 0xbc, 0x9a, 0x78, 0xff]);
        assert!(record.validate().is_ok());
    }

    #[test]
    fn invalid_dimensions_and_short_surface_fail_before_copy() {
        assert!(snapshot(7, 1, -1, 1, &[]).is_err());
        assert!(snapshot(7, 1, 8192, 8192, &[]).is_err());
        assert!(snapshot(7, 1, 2, 1, &[0]).is_err());
        assert!(snapshot(0, 1, 1, 1, &[0]).is_err());
    }
}
