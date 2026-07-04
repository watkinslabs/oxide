extern crate alloc;

use alloc::vec::Vec;

pub const PSF1_MAGIC: [u8; 2] = [0x36, 0x04];
pub const PSF2_MAGIC: [u8; 4] = [0x72, 0xb5, 0x4a, 0x86];
pub const PSF1_MODE512: u8 = 0x01;
pub const PSF1_MODEHASTAB: u8 = 0x02;
pub const PSF1_MODESEQ: u8 = 0x04;
pub const PSF2_HAS_UNICODE_TABLE: u32 = 0x01;

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct Psf1Header {
    pub magic: [u8; 2],
    pub mode: u8,
    pub charsize: u8,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct Psf2Header {
    pub magic: [u8; 4],
    pub version: u32,
    pub headersize: u32,
    pub flags: u32,
    pub length: u32,
    pub charsize: u32,
    pub height: u32,
    pub width: u32,
}

pub(crate) enum GlyphData {
    Static(&'static [u8]),
    Owned(Vec<u8>),
}

impl GlyphData {
    #[inline]
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            GlyphData::Static(s) => s,
            GlyphData::Owned(v) => v,
        }
    }
}

pub struct Font {
    pub width: u32,
    pub height: u32,
    pub(crate) charsize: usize,
    pub(crate) row_bytes: usize,
    pub(crate) count: usize,
    pub(crate) glyphs: GlyphData,
    pub(crate) uni: Vec<(u32, u16)>,
    pub(crate) fallback: u16,
}

impl Font {
    #[inline]
    pub fn glyph_index(&self, cp: u32) -> usize {
        match self.uni.binary_search_by_key(&cp, |&(c, _)| c) {
            Ok(i) => self.uni[i].1 as usize,
            Err(_) => self.fallback as usize,
        }
    }

    #[inline]
    pub fn glyph_row(&self, idx: usize, py: usize) -> u8 {
        if idx >= self.count || py >= self.height as usize {
            return 0;
        }
        self.glyphs.bytes()[idx * self.charsize + py * self.row_bytes]
    }

    #[inline]
    pub fn glyph_bit(&self, idx: usize, py: usize, x: usize) -> bool {
        if idx >= self.count || py >= self.height as usize || x >= self.width as usize {
            return false;
        }
        let off = idx * self.charsize + py * self.row_bytes + x / 8;
        let bytes = self.glyphs.bytes();
        if off >= bytes.len() {
            return false;
        }
        (bytes[off] >> (7 - (x % 8))) & 1 == 1
    }

    pub fn dims(&self) -> (u32, u32, u32) { (self.width, self.height, self.count as u32) }
}

const PSF2_SEPARATOR: u8 = 0xff;
const PSF2_STARTSEQ: u8 = 0xfe;

pub fn parse_psf2(data: &'static [u8]) -> Option<Font> {
    if data.len() < 32 || data[..4] != PSF2_MAGIC {
        return None;
    }
    let rd = |o: usize| -> u32 {
        u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]])
    };
    let headersize = rd(8) as usize;
    let flags = rd(12);
    let count = rd(16) as usize;
    let charsize = rd(20) as usize;
    let height = rd(24);
    let width = rd(28);
    if width == 0 || height == 0 || charsize == 0 || count == 0 {
        return None;
    }
    let row_bytes = ((width + 7) / 8) as usize;
    let glyphs_end = headersize.checked_add(count.checked_mul(charsize)?)?;
    if glyphs_end > data.len() || headersize < 32 {
        return None;
    }
    let glyphs = &data[headersize..glyphs_end];

    let mut uni: Vec<(u32, u16)> = Vec::new();
    if flags & PSF2_HAS_UNICODE_TABLE != 0 {
        parse_unicode_table(&data[glyphs_end..], count, &mut uni);
    } else {
        for i in 0..count.min(0x1_0000) {
            uni.push((i as u32, i as u16));
        }
    }
    uni.sort_by_key(|&(c, _)| c);
    uni.dedup_by_key(|&mut (c, _)| c);
    let fallback = match uni.binary_search_by_key(&0x3f, |&(c, _)| c) {
        Ok(i) => uni[i].1,
        Err(_) => 0,
    };

    Some(Font {
        width,
        height,
        charsize,
        row_bytes,
        count,
        glyphs: GlyphData::Static(glyphs),
        uni,
        fallback,
    })
}

fn parse_unicode_table(tab: &[u8], count: usize, out: &mut Vec<(u32, u16)>) {
    let mut i = 0usize;
    let mut glyph = 0usize;
    let mut in_seq = false;
    while i < tab.len() && glyph < count {
        let b = tab[i];
        if b == PSF2_SEPARATOR {
            glyph += 1;
            in_seq = false;
            i += 1;
            continue;
        }
        if b == PSF2_STARTSEQ {
            in_seq = true;
            i += 1;
            continue;
        }
        let (cp, len) = decode_utf8(&tab[i..]);
        i += len;
        if !in_seq && glyph < 0x1_0000 {
            out.push((cp, glyph as u16));
        }
    }
}

fn decode_utf8(b: &[u8]) -> (u32, usize) {
    if b.is_empty() {
        return (0xfffd, 1);
    }
    let b0 = b[0];
    let cont = |x: u8| (x & 0xc0) == 0x80;
    if b0 < 0x80 {
        (b0 as u32, 1)
    } else if b0 & 0xe0 == 0xc0 && b.len() >= 2 && cont(b[1]) {
        (((b0 as u32 & 0x1f) << 6) | (b[1] as u32 & 0x3f), 2)
    } else if b0 & 0xf0 == 0xe0 && b.len() >= 3 && cont(b[1]) && cont(b[2]) {
        (
            ((b0 as u32 & 0x0f) << 12) | ((b[1] as u32 & 0x3f) << 6) | (b[2] as u32 & 0x3f),
            3,
        )
    } else if b0 & 0xf8 == 0xf0 && b.len() >= 4 && cont(b[1]) && cont(b[2]) && cont(b[3]) {
        (
            ((b0 as u32 & 0x07) << 18)
                | ((b[1] as u32 & 0x3f) << 12)
                | ((b[2] as u32 & 0x3f) << 6)
                | (b[3] as u32 & 0x3f),
            4,
        )
    } else {
        (0xfffd, 1)
    }
}

#[cfg(test)]
pub fn set_font_with_map(
    width: u32, height: u32, count: u32, stride: usize, data: &[u8],
    mut uni: Vec<(u32, u16)>, fallback: u16,
) {
    uni.sort_by_key(|&(c, _)| c);
    uni.dedup_by_key(|&mut (c, _)| c);
    if let Ok(font) = build_font(width, height, count, stride, data, uni, fallback) {
        crate::font::runtime::install(font);
    }
}

pub(crate) fn build_font(
    width: u32, height: u32, count: u32, stride: usize, data: &[u8],
    uni: Vec<(u32, u16)>, fallback: u16,
) -> Result<Font, ()> {
    if width == 0 || width > 32 || height == 0 || height > 32 || count == 0 || count > 512 {
        return Err(());
    }
    let count = count as usize;
    let row_bytes = ((width + 7) / 8) as usize;
    let charsize = row_bytes * height as usize;
    if stride < charsize || data.len() < count * stride {
        return Err(());
    }
    let mut glyphs = Vec::with_capacity(count * charsize);
    for i in 0..count {
        let base = i * stride;
        glyphs.extend_from_slice(&data[base..base + charsize]);
    }
    Ok(Font {
        width,
        height,
        charsize,
        row_bytes,
        count,
        glyphs: GlyphData::Owned(glyphs),
        uni,
        fallback: fallback.min(count as u16 - 1),
    })
}

pub(crate) fn serialize(f: &Font, stride: usize) -> (u32, u32, u32, Vec<u8>) {
    let mut out = alloc::vec![0u8; f.count * stride];
    let h = f.height as usize;
    let rb = f.row_bytes;
    let src = f.glyphs.bytes();
    for i in 0..f.count {
        for py in 0..h {
            for b in 0..rb {
                out[i * stride + py * rb + b] = src[i * f.charsize + py * rb + b];
            }
        }
    }
    (f.width, f.height, f.count as u32, out)
}
