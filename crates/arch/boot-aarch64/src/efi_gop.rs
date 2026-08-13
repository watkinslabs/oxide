//! UEFI GOP mode validation and BootInfo framebuffer conversion.

use boot_info::{BootFramebuffer, BootFramebufferBitfield, BootFramebufferKind};

pub(crate) const PIXEL_RGB_RESERVED_8BIT_PER_COLOR: u32 = 0;
pub(crate) const PIXEL_BGR_RESERVED_8BIT_PER_COLOR: u32 = 1;
pub(crate) const PIXEL_BIT_MASK: u32 = 2;

#[derive(Copy, Clone)]
pub(crate) struct GopMode {
    pub(crate) base_pa: u64,
    pub(crate) bytes: u64,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) pixel_format: u32,
    pub(crate) red_mask: u32,
    pub(crate) green_mask: u32,
    pub(crate) blue_mask: u32,
    pub(crate) reserved_mask: u32,
    pub(crate) pixels_per_scanline: u32,
}

fn bits(mask: u32) -> Option<BootFramebufferBitfield> {
    if mask == 0 { return None; }
    let offset = mask.trailing_zeros() as u8;
    let length = mask.count_ones() as u8;
    let expected = if length == 32 { u32::MAX } else { (((1u64 << length) - 1) as u32) << offset };
    (mask == expected).then_some(BootFramebufferBitfield { offset, length })
}

/// Decode a GOP linear framebuffer only when its complete visible extent and
/// packed-RGB channel layout are representable by the generic framebuffer.
/// # C: O(1)
pub(crate) fn framebuffer(mode: GopMode) -> Option<BootFramebuffer> {
    let (bpp, red, green, blue) = match mode.pixel_format {
        PIXEL_RGB_RESERVED_8BIT_PER_COLOR => (32, BootFramebufferBitfield { offset: 0, length: 8 },
                                               BootFramebufferBitfield { offset: 8, length: 8 },
                                               BootFramebufferBitfield { offset: 16, length: 8 }),
        PIXEL_BGR_RESERVED_8BIT_PER_COLOR => (32, BootFramebufferBitfield { offset: 16, length: 8 },
                                               BootFramebufferBitfield { offset: 8, length: 8 },
                                               BootFramebufferBitfield { offset: 0, length: 8 }),
        PIXEL_BIT_MASK => {
            let red = bits(mode.red_mask)?;
            let green = bits(mode.green_mask)?;
            let blue = bits(mode.blue_mask)?;
            let reserved = if mode.reserved_mask == 0 { None } else { Some(bits(mode.reserved_mask)?) };
            if mode.red_mask & mode.green_mask != 0 || mode.red_mask & mode.blue_mask != 0
                || mode.green_mask & mode.blue_mask != 0
                || reserved.is_some_and(|_| (mode.reserved_mask & (mode.red_mask | mode.green_mask | mode.blue_mask)) != 0) { return None; }
            let end = |field: BootFramebufferBitfield| u32::from(field.offset) + u32::from(field.length);
            let used = reserved.map(end).unwrap_or(0).max(end(red)).max(end(green)).max(end(blue));
            let bpp = match used { 1..=16 => 16, 17..=24 => 24, 25..=32 => 32, _ => return None };
            (bpp, red, green, blue)
        }
        _ => return None,
    };
    let pitch = mode.pixels_per_scanline.checked_mul(u32::from(bpp) / 8)?;
    let visible = u64::from(pitch).checked_mul(u64::from(mode.height))?;
    if mode.base_pa == 0 || visible == 0 || visible > mode.bytes { return None; }
    let fb = BootFramebuffer { base_pa: mode.base_pa, pitch, width: mode.width, height: mode.height,
        bpp, kind: BootFramebufferKind::Rgb, red, green, blue, _pad: [0; 2] };
    fb.byte_len().is_some().then_some(fb)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(format: u32) -> GopMode { GopMode { base_pa: 0x4000_0000, bytes: 4096 * 768,
        width: 1024, height: 768, pixel_format: format, red_mask: 0, green_mask: 0, blue_mask: 0, reserved_mask: 0, pixels_per_scanline: 1024 } }

    #[test]
    fn standard_gop_formats_map_to_packed_rgb() {
        let rgb = framebuffer(mode(PIXEL_RGB_RESERVED_8BIT_PER_COLOR)).unwrap();
        assert_eq!(rgb.red.offset, 0);
        assert_eq!(rgb.blue.offset, 16);
        let bgr = framebuffer(mode(PIXEL_BGR_RESERVED_8BIT_PER_COLOR)).unwrap();
        assert_eq!(bgr.red.offset, 16);
        assert_eq!(bgr.blue.offset, 0);
    }

    #[test]
    fn bitmask_requires_contiguous_nonoverlapping_channels_and_vram() {
        let mut bitmask = mode(PIXEL_BIT_MASK);
        bitmask.red_mask = 0x00ff_0000; bitmask.green_mask = 0x0000_ff00; bitmask.blue_mask = 0x0000_00ff;
        assert!(framebuffer(bitmask).is_some());
        bitmask.red_mask = 0xf800; bitmask.green_mask = 0x07e0; bitmask.blue_mask = 0x001f;
        let rgb565 = framebuffer(bitmask).unwrap();
        assert_eq!((rgb565.bpp, rgb565.pitch), (16, 2048));
        bitmask.blue_mask = 0x0000_0005;
        assert!(framebuffer(bitmask).is_none());
        bitmask = mode(PIXEL_BIT_MASK);
        bitmask.red_mask = 0x00ff_0000; bitmask.green_mask = 0x0000_ff00; bitmask.blue_mask = 0x0000_00ff; bitmask.reserved_mask = 0xff00_0000;
        assert!(framebuffer(bitmask).is_some());
        bitmask.reserved_mask = 0x00ff_0000;
        assert!(framebuffer(bitmask).is_none());
        bitmask = mode(PIXEL_RGB_RESERVED_8BIT_PER_COLOR);
        bitmask.bytes -= 1;
        assert!(framebuffer(bitmask).is_none());
    }
}
