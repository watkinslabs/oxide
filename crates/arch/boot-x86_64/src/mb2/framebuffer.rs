use boot_info::{BootFramebuffer, BootFramebufferBitfield, BootFramebufferKind};

const TAG_TYPE_FRAMEBUFFER: u32 = 8;
const FRAMEBUFFER_TYPE_RGB: u8 = 1;
const RGB_TAG_BYTES: usize = 38;

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn le64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off], b[off + 1], b[off + 2], b[off + 3],
        b[off + 4], b[off + 5], b[off + 6], b[off + 7],
    ])
}

/// Decode a Multiboot2 framebuffer information tag, accepting only validated
/// packed-RGB modes that the simple framebuffer driver can expose exactly.
/// # C: O(1)
pub(super) fn parse_tag(tag: &[u8]) -> Option<BootFramebuffer> {
    if tag.len() < RGB_TAG_BYTES
        || le32(tag, 0) != TAG_TYPE_FRAMEBUFFER
        || le32(tag, 4) < RGB_TAG_BYTES as u32
        || tag[29] != FRAMEBUFFER_TYPE_RGB
    {
        return None;
    }
    let fb = BootFramebuffer {
        base_pa: le64(tag, 8),
        pitch: le32(tag, 16),
        width: le32(tag, 20),
        height: le32(tag, 24),
        bpp: tag[28],
        kind: BootFramebufferKind::Rgb,
        red: BootFramebufferBitfield { offset: tag[32], length: tag[33] },
        green: BootFramebufferBitfield { offset: tag[34], length: tag[35] },
        blue: BootFramebufferBitfield { offset: tag[36], length: tag[37] },
        _pad: [0; 2],
    };
    fb.byte_len().map(|_| fb)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rgb_tag() -> [u8; RGB_TAG_BYTES] {
        let mut tag = [0u8; RGB_TAG_BYTES];
        tag[0..4].copy_from_slice(&TAG_TYPE_FRAMEBUFFER.to_le_bytes());
        tag[4..8].copy_from_slice(&(RGB_TAG_BYTES as u32).to_le_bytes());
        tag[8..16].copy_from_slice(&0xfd00_0000u64.to_le_bytes());
        tag[16..20].copy_from_slice(&4096u32.to_le_bytes());
        tag[20..24].copy_from_slice(&1024u32.to_le_bytes());
        tag[24..28].copy_from_slice(&768u32.to_le_bytes());
        tag[28] = 32;
        tag[29] = FRAMEBUFFER_TYPE_RGB;
        tag[32..38].copy_from_slice(&[16, 8, 8, 8, 0, 8]);
        tag
    }

    #[test]
    fn parses_rgb_information_tag_exactly() {
        let fb = parse_tag(&rgb_tag()).expect("valid RGB tag");
        assert_eq!(fb.base_pa, 0xfd00_0000);
        assert_eq!((fb.width, fb.height, fb.pitch, fb.bpp), (1024, 768, 4096, 32));
        assert_eq!(fb.red, BootFramebufferBitfield { offset: 16, length: 8 });
    }

    #[test]
    fn rejects_text_mode_and_invalid_geometry() {
        let mut tag = rgb_tag();
        tag[29] = 2;
        assert_eq!(parse_tag(&tag), None);
        tag = rgb_tag();
        tag[16..20].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(parse_tag(&tag), None);
    }
}
