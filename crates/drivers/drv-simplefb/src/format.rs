use boot_info::{BootFramebuffer, BootFramebufferBitfield};

fn fb_bitfield(f: BootFramebufferBitfield) -> fbdev::FbBitfield {
    fbdev::FbBitfield { offset: u32::from(f.offset), length: u32::from(f.length), msb_right: 0 }
}

/// Exact fbdev mode for a validated boot framebuffer.
/// # C: O(1)
pub(crate) fn fb_var(fb: BootFramebuffer) -> Option<fbdev::FbVarScreeninfo> {
    fb.byte_len()?;
    let mut var = fbdev::FbVarScreeninfo::default();
    var.xres = fb.width;
    var.yres = fb.height;
    var.xres_virtual = fb.width;
    var.yres_virtual = fb.height;
    var.bits_per_pixel = u32::from(fb.bpp);
    var.red = fb_bitfield(fb.red);
    var.green = fb_bitfield(fb.green);
    var.blue = fb_bitfield(fb.blue);
    var.transp = fbdev::FbBitfield::default();
    Some(var)
}

fn channel(v: u8, f: BootFramebufferBitfield) -> u32 {
    let max = (1u32 << f.length) - 1;
    (((u32::from(v) * max + 127) / 255) & max) << f.offset
}

fn encode(px: u32, fb: BootFramebuffer) -> u32 {
    let r = ((px >> 16) & 0xff) as u8;
    let g = ((px >> 8) & 0xff) as u8;
    let b = (px & 0xff) as u8;
    channel(r, fb.red) | channel(g, fb.green) | channel(b, fb.blue)
}

fn canonical_xrgb8888(fb: BootFramebuffer) -> bool {
    fb.bpp == 32
        && fb.red == BootFramebufferBitfield { offset: 16, length: 8 }
        && fb.green == BootFramebufferBitfield { offset: 8, length: 8 }
        && fb.blue == BootFramebufferBitfield { offset: 0, length: 8 }
}

/// Copy one fbcon damage rectangle from its 0x00RRGGBB surface into native
/// firmware layout. Rows retain firmware pitch padding.
/// # C: O(rect.w * rect.h)
pub(crate) fn copy_damage(
    pixels: &[u8],
    dst: &mut [u8],
    rect: fbcon::kernel::FlushRect,
    fb: BootFramebuffer,
) {
    let Some(fb_len) = fb.byte_len() else { return };
    if dst.len() < fb_len as usize { return; }
    let x1 = rect.x.saturating_add(rect.w).min(fb.width).min(rect.stride_px);
    let y1 = rect.y.saturating_add(rect.h).min(fb.height);
    if rect.x >= x1 || rect.y >= y1 { return; }
    let native_bytes = usize::from(fb.bpp).div_ceil(8);
    for y in rect.y..y1 {
        let src_px = y as usize * rect.stride_px as usize + rect.x as usize;
        let count = (x1 - rect.x) as usize;
        let src_off = src_px * 4;
        let src_end = match src_off.checked_add(count * 4) { Some(end) => end, None => return };
        if src_end > pixels.len() { return; }
        let dst_off = y as usize * fb.pitch as usize + rect.x as usize * native_bytes;
        let dst_end = match dst_off.checked_add(count * native_bytes) { Some(end) => end, None => return };
        if dst_end > dst.len() { return; }
        if canonical_xrgb8888(fb) {
            dst[dst_off..dst_end].copy_from_slice(&pixels[src_off..src_end]);
            continue;
        }
        for x in 0..count {
            let off = src_off + x * 4;
            let px = u32::from_ne_bytes([pixels[off], pixels[off + 1], pixels[off + 2], pixels[off + 3]]);
            let encoded = encode(px, fb).to_le_bytes();
            let out = dst_off + x * native_bytes;
            dst[out..out + native_bytes].copy_from_slice(&encoded[..native_bytes]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boot_info::BootFramebufferKind;

    fn mode(bpp: u8, pitch: u32, red: (u8, u8), green: (u8, u8), blue: (u8, u8)) -> BootFramebuffer {
        BootFramebuffer {
            base_pa: 0xe000_0000, pitch, width: 2, height: 2, bpp,
            kind: BootFramebufferKind::Rgb,
            red: BootFramebufferBitfield { offset: red.0, length: red.1 },
            green: BootFramebufferBitfield { offset: green.0, length: green.1 },
            blue: BootFramebufferBitfield { offset: blue.0, length: blue.1 },
            _pad: [0; 2],
        }
    }

    #[test]
    fn xrgb_damage_copy_preserves_pitch_and_untouched_rows() {
        let fb = mode(32, 12, (16, 8), (8, 8), (0, 8));
        let pixels: [u32; 4] = [0x0011_2233, 0x0044_5566, 0x0077_8899, 0x00aa_bbcc];
        // SAFETY: pixels is four initialized u32 values; its byte view has the
        // same live extent and requires only byte alignment.
        let src = unsafe {
            core::slice::from_raw_parts(pixels.as_ptr() as *const u8, 16)
        };
        let mut dst = [0xa5u8; 24];
        copy_damage(src, &mut dst, fbcon::kernel::FlushRect { x: 1, y: 0, w: 1, h: 2, stride_px: 2 }, fb);
        assert_eq!(&dst[4..8], &0x0044_5566u32.to_ne_bytes());
        assert_eq!(&dst[16..20], &0x00aa_bbccu32.to_ne_bytes());
        assert_eq!(&dst[8..12], &[0xa5; 4]);
    }

    #[test]
    fn converts_renderer_rgb_to_rgb565() {
        let fb = mode(16, 4, (11, 5), (5, 6), (0, 5));
        let pixels: [u32; 4] = [0x00ff_0000, 0x0000_ff00, 0x0000_00ff, 0x00ff_ffff];
        // SAFETY: pixels is four initialized u32 values; its byte view has the
        // same live extent and requires only byte alignment.
        let src = unsafe {
            core::slice::from_raw_parts(pixels.as_ptr() as *const u8, 16)
        };
        let mut dst = [0u8; 8];
        copy_damage(src, &mut dst, fbcon::kernel::FlushRect { x: 0, y: 0, w: 2, h: 2, stride_px: 2 }, fb);
        assert_eq!(u16::from_le_bytes([dst[0], dst[1]]), 0xf800);
        assert_eq!(u16::from_le_bytes([dst[2], dst[3]]), 0x07e0);
        assert_eq!(u16::from_le_bytes([dst[4], dst[5]]), 0x001f);
        assert_eq!(u16::from_le_bytes([dst[6], dst[7]]), 0xffff);
    }
}
