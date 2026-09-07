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
/// Only the damaged sub-rectangle travels, at its own stride: the display
/// retains the surface across frames and repaints a re-expose from its own
/// copy, so a whole window on the wire is a line of typed text's worth of
/// pixels plus the rest of the window nobody changed. The payload states the
/// surface extent it belongs to and the sub-rectangle it carries.
/// # C: O(damage width * damage height)
pub(crate) fn snapshot(hwnd: u32, sequence: u64, width: i32, height: i32, pixels: &[u32], damage: Damage) -> Result<Record, Error> {
    let width = u32::try_from(width).map_err(|_| Error::Payload)?;
    let height = u32::try_from(height).map_err(|_| Error::Payload)?;
    let row = u32::try_from(damage.right.checked_sub(damage.left).ok_or(Error::Overflow)?).map_err(|_| Error::Payload)?.checked_mul(4).ok_or(Error::Overflow)?;
    let bytes = wire::frame_pixel_len(width, height, row, wire::PIXEL_BGRA8888, damage)?;
    let surface = (width as usize).checked_mul(height as usize).ok_or(Error::Overflow)?;
    if pixels.len() != surface { return Err(Error::Length); }
    let mut payload = Vec::new();
    payload.try_reserve_exact(wire::FRAME_HEADER_BYTES + bytes).map_err(|_| Error::Allocation)?;
    for value in [width, height, row, wire::PIXEL_BGRA8888] {
        payload.extend_from_slice(&value.to_le_bytes());
    }
    payload.extend_from_slice(&damage.encode());
    for y in damage.top as usize..damage.bottom as usize {
        let start = y * width as usize + damage.left as usize;
        for pixel in &pixels[start..start + (row / 4) as usize] {
            payload.extend_from_slice(&(pixel | 0xff00_0000).to_le_bytes());
        }
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

    /// A typed character damages one line of a window. The payload that
    /// carries it must be that line, not the window: the whole surface is
    /// what made a keystroke cost a megabyte and a half of copying.
    #[test]
    fn a_one_line_damage_carries_that_line_and_not_the_window() {
        const W: i32 = 725; const H: i32 = 528; const LINE: i32 = 14;
        let pixels = alloc::vec![0x00ab_cdefu32; (W * H) as usize];
        let line = Damage { left: 3, top: 40, right: W - 3, bottom: 40 + LINE };
        let record = snapshot(7, 1, W, H, &pixels, line).unwrap();
        let carried = ((W - 6) * LINE * 4) as usize;
        assert_eq!(record.payload.len(), wire::FRAME_HEADER_BYTES + carried);
        assert!(record.payload.len() * 24 < (W * H * 4) as usize, "one line still costs a whole-surface payload");
        assert_eq!(u32::from_le_bytes(record.payload[0..4].try_into().unwrap()), W as u32);
        assert_eq!(u32::from_le_bytes(record.payload[4..8].try_into().unwrap()), H as u32);
        assert_eq!(u32::from_le_bytes(record.payload[8..12].try_into().unwrap()), ((W - 6) * 4) as u32);
        assert_eq!(Damage::decode(&record.payload[16..32]).unwrap(), line);
        assert!(record.validate().is_ok());
    }

    /// The rows a sub-rectangle carries are its own, taken from the surface
    /// at the damage origin - not the surface's first rows.
    #[test]
    fn the_carried_rows_are_the_damaged_ones_at_their_own_origin() {
        let pixels: [u32; 12] = core::array::from_fn(|i| i as u32);
        let part = Damage { left: 1, top: 1, right: 3, bottom: 3 };
        let record = snapshot(7, 1, 4, 3, &pixels, part).unwrap();
        let carried: alloc::vec::Vec<u32> = record.payload[32..].chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()) & 0x00ff_ffff).collect();
        assert_eq!(carried, alloc::vec![5, 6, 9, 10]);
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
        assert_eq!(record.payload.len(), wire::FRAME_HEADER_BYTES + 3 * 2 * 4);
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
