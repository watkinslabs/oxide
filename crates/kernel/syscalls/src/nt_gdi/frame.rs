//! Convert the canonical GDI surface into an owned, bounded bridge frame.

use alloc::vec::Vec;
use syscall::nt_compositor::{self as wire, Damage, Error, Opcode, Record};

/// Where client-origin paint coverage lands in the window backing it was
/// merged into. The coverage a paint admits is in client coordinates and the
/// surface the display is given is the whole window, so the offset between
/// them is the client origin inside that window. # C: O(1)
pub(crate) fn client_damage(bounds: ipc::win32_window::WindowRect, client: ipc::win32_gdi::Rect) -> Option<Damage> {
    Some(Damage { left: bounds.left.checked_add(client.left)?, top: bounds.top.checked_add(client.top)?,
        right: bounds.right.checked_add(client.left)?, bottom: bounds.bottom.checked_add(client.top)? })
}

/// Snapshot XRGB pixels while the caller protects the GDI surface. The returned
/// record has no borrowed surface memory and is enqueued only after unlocking.
/// The surface travels whole because a re-expose repaints from it; `damage`
/// names the part of it that changed, which is the only part the display has
/// to be given. A caller with no narrower coverage passes the whole surface.
/// # C: O(width * height)
pub(crate) fn snapshot(hwnd: u32, sequence: u64, width: i32, height: i32, pixels: &[u32], damage: Damage) -> Result<Record, Error> {
    let width = u32::try_from(width).map_err(|_| Error::Payload)?;
    let height = u32::try_from(height).map_err(|_| Error::Payload)?;
    let stride = width.checked_mul(4).ok_or(Error::Overflow)?;
    let bytes = wire::pixel_len(width, height, stride, wire::PIXEL_BGRA8888)?;
    if pixels.len() != bytes / 4 { return Err(Error::Length); }
    let mut payload = Vec::new();
    if !damage.valid(width, height) { return Err(Error::Payload); }
    payload.try_reserve_exact(wire::FRAME_HEADER_BYTES + bytes).map_err(|_| Error::Allocation)?;
    for value in [width, height, stride, wire::PIXEL_BGRA8888] {
        payload.extend_from_slice(&value.to_le_bytes());
    }
    payload.extend_from_slice(&damage.encode());
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
        let whole = Damage { left: 0, top: 0, right: 2, bottom: 1 };
        let record = snapshot(7, 1, 2, 1, &pixels, whole).unwrap();
        pixels.fill(0);
        assert_eq!(record.header.hwnd, 7);
        assert_eq!(Damage::decode(&record.payload[16..32]).unwrap(), whole);
        assert_eq!(&record.payload[32..], &[0x56, 0x34, 0x12, 0xff, 0xbc, 0x9a, 0x78, 0xff]);
        assert!(record.validate().is_ok());
    }

    #[test]
    fn client_coverage_reaches_the_backing_at_the_client_origin() {
        let bounds = ipc::win32_window::WindowRect { left: 4, top: 1, right: 725, bottom: 15 };
        let client = ipc::win32_gdi::Rect { left: 3, top: 27, right: 728, bottom: 555 };
        assert_eq!(client_damage(bounds, client), Some(Damage { left: 7, top: 28, right: 728, bottom: 42 }));
        let origin = ipc::win32_gdi::Rect { left: 0, top: 0, right: 725, bottom: 528 };
        assert_eq!(client_damage(bounds, origin), Some(Damage { left: 4, top: 1, right: 725, bottom: 15 }));
        let far = ipc::win32_window::WindowRect { left: 0, top: 0, right: i32::MAX, bottom: 1 };
        assert_eq!(client_damage(far, client), None);
    }

    #[test]
    fn a_partial_damage_travels_and_an_impossible_one_is_refused() {
        let pixels = [0u32; 8];
        let part = Damage { left: 1, top: 0, right: 4, bottom: 2 };
        let record = snapshot(7, 1, 4, 2, &pixels, part).unwrap();
        assert_eq!(Damage::decode(&record.payload[16..32]).unwrap(), part);
        assert!(record.validate().is_ok());
        for bad in [Damage { left: 0, top: 0, right: 5, bottom: 2 }, Damage { left: 2, top: 0, right: 2, bottom: 2 },
            Damage { left: -1, top: 0, right: 4, bottom: 2 }, Damage { left: 0, top: 0, right: 4, bottom: 3 }] {
            assert_eq!(snapshot(7, 1, 4, 2, &pixels, bad).err(), Some(Error::Payload));
        }
    }

    #[test]
    fn invalid_dimensions_and_short_surface_fail_before_copy() {
        let whole = |w, h| Damage { left: 0, top: 0, right: w, bottom: h };
        assert!(snapshot(7, 1, -1, 1, &[], whole(1, 1)).is_err());
        assert!(snapshot(7, 1, 8192, 8192, &[], whole(8192, 8192)).is_err());
        assert!(snapshot(7, 1, 2, 1, &[0], whole(2, 1)).is_err());
        assert!(snapshot(0, 1, 1, 1, &[0], whole(1, 1)).is_err());
    }
}
