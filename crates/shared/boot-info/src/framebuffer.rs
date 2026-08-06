/// One color channel in a packed framebuffer pixel.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BootFramebufferBitfield {
    pub offset: u8,
    pub length: u8,
}

/// Boot framebuffer mode kind.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BootFramebufferKind {
    None = 0,
    Rgb = 1,
}

/// Linear framebuffer surfaced by the architecture handoff.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BootFramebuffer {
    pub base_pa: u64,
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
    pub kind: BootFramebufferKind,
    pub red: BootFramebufferBitfield,
    pub green: BootFramebufferBitfield,
    pub blue: BootFramebufferBitfield,
    pub _pad: [u8; 2],
}

impl BootFramebuffer {
    pub const EMPTY: Self = Self {
        base_pa: 0,
        pitch: 0,
        width: 0,
        height: 0,
        bpp: 0,
        kind: BootFramebufferKind::None,
        red: BootFramebufferBitfield { offset: 0, length: 0 },
        green: BootFramebufferBitfield { offset: 0, length: 0 },
        blue: BootFramebufferBitfield { offset: 0, length: 0 },
        _pad: [0; 2],
    };

    /// Bytes occupied by the visible scanout, after validating the packed-RGB
    /// geometry and channel masks accepted by the simple framebuffer driver.
    /// # C: O(1)
    pub fn byte_len(self) -> Option<u64> {
        if self.kind != BootFramebufferKind::Rgb
            || self.base_pa == 0
            || self.width == 0
            || self.height == 0
            || !matches!(self.bpp, 16 | 24 | 32)
        {
            return None;
        }
        let pixel_bytes = u32::from(self.bpp).div_ceil(8);
        let row_bytes = self.width.checked_mul(pixel_bytes)?;
        if self.pitch < row_bytes { return None; }
        let valid = |f: BootFramebufferBitfield| {
            f.length != 0 && u16::from(f.offset) + u16::from(f.length) <= u16::from(self.bpp)
        };
        if !valid(self.red) || !valid(self.green) || !valid(self.blue) { return None; }
        let mask = |f: BootFramebufferBitfield| -> u64 {
            ((1u64 << f.length) - 1) << f.offset
        };
        let (r, g, b) = (mask(self.red), mask(self.green), mask(self.blue));
        if r & g != 0 || r & b != 0 || g & b != 0 { return None; }
        let len = u64::from(self.pitch).checked_mul(u64::from(self.height))?;
        if len > u64::from(u32::MAX) { return None; }
        self.base_pa.checked_add(len)?;
        Some(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xrgb() -> BootFramebuffer {
        BootFramebuffer {
            base_pa: 0xfd00_0000,
            pitch: 4096,
            width: 1024,
            height: 768,
            bpp: 32,
            kind: BootFramebufferKind::Rgb,
            red: BootFramebufferBitfield { offset: 16, length: 8 },
            green: BootFramebufferBitfield { offset: 8, length: 8 },
            blue: BootFramebufferBitfield { offset: 0, length: 8 },
            _pad: [0; 2],
        }
    }

    #[test]
    fn validates_packed_rgb_extent() {
        assert_eq!(xrgb().byte_len(), Some(4096 * 768));
    }

    #[test]
    fn rejects_short_pitch_and_overlapping_masks() {
        let mut fb = xrgb();
        fb.pitch = 4095;
        assert_eq!(fb.byte_len(), None);
        fb.pitch = 4096;
        fb.green.offset = 16;
        assert_eq!(fb.byte_len(), None);
    }
}
