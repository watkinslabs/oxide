// Console font: PSF2 parser + `conv_uni_to_pc` unicode map (the Linux
// fbcon glyph path). The kernel's built-in default is the classic IBM VGA
// `default8x16.psfu` (256 glyphs, 8×16, public domain) embedded below —
// the SAME format `setfont`/KDFONTOP loads at runtime, so a later font
// swap reuses this exact parser.
//
// Linux renders a cell by mapping its Unicode codepoint through the font's
// unicode table to a glyph index (`conv_uni_to_pc`), then blitting that
// glyph's bitmap. The VT emulator already stores real Unicode in each cell
// (DEC special-graphics `ESC(0` line-drawing → U+25xx, accented Latin,
// etc.); this module is what turns those codepoints into real glyphs
// instead of the old ASCII-only `?` fallback.
//
// Host-testable: `include_bytes!` + the parser are plain data, so
// `cargo test -p fbcon` exercises the PSF2 decode + the unicode map
// (box-drawing, accented Latin) without a kernel boot.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

/// Embedded built-in console font (IBM VGA `default8x16.psfu`, PSF2 with a
/// unicode table). 256 glyphs, 8×16, flags=HAS_UNICODE_TABLE.
static DEFAULT_PSF: &[u8] = include_bytes!("default8x16.psfu");

/// PSF2 magic (`drivers/tty/vt/`: `PSF2_MAGIC0..3`).
const PSF2_MAGIC: [u8; 4] = [0x72, 0xb5, 0x4a, 0x86];
/// PSF2 flag: a unicode description table follows the glyph bitmaps.
const PSF2_HAS_UNICODE_TABLE: u32 = 0x01;
/// Unicode-table terminators: `0xFF` ends a glyph's entry; `0xFE` starts a
/// combining/ligature sequence within an entry (we map only the primary
/// codepoints before the first `0xFE`).
const PSF2_SEPARATOR: u8 = 0xff;
const PSF2_STARTSEQ: u8 = 0xfe;

/// A parsed console font: glyph bitmaps + the unicode→glyph-index map.
/// `glyphs` borrows the embedded (or, later, the loaded) blob; `uni` is
/// the sorted `conv_uni_to_pc` table.
pub struct Font {
    /// Glyph width in pixels (8 for the built-in).
    pub width: u32,
    /// Glyph height in pixels / scanlines (16 for the built-in).
    pub height: u32,
    /// Bytes per glyph (`bytes_per_row * height`).
    charsize: usize,
    /// Bytes per glyph scanline (`ceil(width/8)`).
    row_bytes: usize,
    /// Number of glyphs in the font.
    count: usize,
    /// Glyph bitmap region: `count * charsize` bytes, MSB = leftmost pixel.
    glyphs: &'static [u8],
    /// `conv_uni_to_pc`: (codepoint, glyph-index) sorted by codepoint.
    uni: Vec<(u32, u16)>,
    /// Resolved glyph index for U+FFFD/`?` — the fallback for an unmapped
    /// codepoint (Linux uses the font's `def` glyph).
    fallback: u16,
}

impl Font {
    /// Map a Unicode codepoint to a glyph index via the font's unicode
    /// table (`conv_uni_to_pc`); unmapped codepoints fall back to the
    /// `?`/replacement glyph. # C: O(log N) binary search.
    #[inline]
    pub fn glyph_index(&self, cp: u32) -> usize {
        match self.uni.binary_search_by_key(&cp, |&(c, _)| c) {
            Ok(i) => self.uni[i].1 as usize,
            Err(_) => self.fallback as usize,
        }
    }

    /// One scanline (`py < height`) of glyph `idx` as a left-justified byte
    /// (MSB = leftmost pixel) — width ≤ 8 fonts use bit `7-x`. Out-of-range
    /// returns 0 (blank). # C: O(1).
    #[inline]
    pub fn glyph_row(&self, idx: usize, py: usize) -> u8 {
        if idx >= self.count || py >= self.height as usize {
            return 0;
        }
        // First byte of the scanline (width ≤ 8 → 1 byte/row).
        self.glyphs[idx * self.charsize + py * self.row_bytes]
    }
}

/// Parse a PSF2 font blob into a `Font`. Returns `None` on a bad magic,
/// truncated header/glyphs, or zero geometry. Builds the `conv_uni_to_pc`
/// table from the unicode description table when present; otherwise the
/// identity map (glyph i = codepoint i, the PSF "no unicode table" case).
/// # C: O(unicode-table bytes) — single pass.
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
        // No table: glyph i answers codepoint i (PSF ascii/latin1 default).
        for i in 0..count.min(0x1_0000) {
            uni.push((i as u32, i as u16));
        }
    }
    // Sort + dedup by codepoint (keep the first glyph mapped to it) for
    // binary search in `conv_uni_to_pc`.
    uni.sort_by_key(|&(c, _)| c);
    uni.dedup_by_key(|&mut (c, _)| c);

    // Fallback glyph: '?' (U+003F) if mapped, else glyph 0.
    let fallback = match uni.binary_search_by_key(&0x3f, |&(c, _)| c) {
        Ok(i) => uni[i].1,
        Err(_) => 0,
    };

    Some(Font { width, height, charsize, row_bytes, count, glyphs, uni, fallback })
}

/// Parse the PSF2 unicode description table: for each glyph `0..count`, a
/// run of UTF-8 codepoints terminated by `0xFF`; a `0xFE` begins a
/// combining/ligature sequence we stop mapping at (only the primary
/// codepoints before it index this glyph, as Linux's `conv_uni_to_pc` does
/// for single-cell glyphs). # C: O(table bytes).
fn parse_unicode_table(tab: &[u8], count: usize, out: &mut Vec<(u32, u16)>) {
    let mut i = 0usize;
    let mut glyph = 0usize;
    let mut in_seq = false; // inside a 0xFE combining run → skip
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
        // Decode one UTF-8 scalar starting at `i`.
        let (cp, len) = decode_utf8(&tab[i..]);
        i += len;
        if !in_seq && glyph < 0x1_0000 {
            out.push((cp, glyph as u16));
        }
    }
}

/// Minimal UTF-8 scalar decode (no_std): returns (codepoint, bytes
/// consumed). A malformed lead byte consumes 1 byte as U+FFFD so the table
/// walk always advances. # C: O(1).
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
        (((b0 as u32 & 0x0f) << 12) | ((b[1] as u32 & 0x3f) << 6) | (b[2] as u32 & 0x3f), 3)
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

/// Process-wide active console font, parsed once from the embedded default
/// (or a later `setfont`/KDFONTOP load). `null` until first use.
static ACTIVE: AtomicPtr<Font> = AtomicPtr::new(core::ptr::null_mut());

/// The active console font, parsing + installing the built-in default on
/// first call. Leaks the `Font` intentionally (kernel-lifetime, one font).
/// # C: O(font parse) first call, O(1) after.
pub fn active() -> &'static Font {
    let p = ACTIVE.load(Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: a non-null ACTIVE was published by a prior call via Box::into_raw of a leaked Font that lives for the kernel lifetime; &* yields a shared ref and Font is read-only after install.
        return unsafe { &*p };
    }
    let font = parse_psf2(DEFAULT_PSF).expect("built-in default8x16.psfu must parse");
    let raw = Box::into_raw(Box::new(font));
    match ACTIVE.compare_exchange(core::ptr::null_mut(), raw, Ordering::AcqRel, Ordering::Acquire) {
        // SAFETY: we won the CAS; `raw` came from Box::into_raw above and is now the unique published pointer, valid for the kernel lifetime.
        Ok(_) => unsafe { &*raw },
        Err(winner) => {
            // Lost the race: drop ours, use the winner.
            // SAFETY: `raw` is our own Box::into_raw that no one else observed (CAS failed before publishing it); reclaiming it frees exactly our allocation.
            drop(unsafe { Box::from_raw(raw) });
            // SAFETY: `winner` is the pointer another thread published via the same Box::into_raw path; it is valid for the kernel lifetime.
            unsafe { &*winner }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_font_parses_8x16_256() {
        let f = parse_psf2(DEFAULT_PSF).expect("parse");
        assert_eq!(f.width, 8);
        assert_eq!(f.height, 16);
        assert_eq!(f.count, 256);
        assert_eq!(f.charsize, 16);
    }

    #[test]
    fn ascii_maps_to_cp437_positions() {
        let f = parse_psf2(DEFAULT_PSF).unwrap();
        // CP437 = ASCII in the low range; the unicode table reflects it.
        assert_eq!(f.glyph_index('A' as u32), 65);
        assert_eq!(f.glyph_index('?' as u32), 63);
        assert_eq!(f.glyph_index(' ' as u32), 32);
    }

    #[test]
    fn box_drawing_and_blocks_map_to_real_glyphs() {
        let f = parse_psf2(DEFAULT_PSF).unwrap();
        // The DEC special-graphics / box-drawing codepoints the emulator
        // stores must resolve to the CP437 line-drawing glyphs, NOT '?'.
        assert_eq!(f.glyph_index(0x2500), 196); // ─ horizontal
        assert_eq!(f.glyph_index(0x2502), 179); // │ vertical
        assert_eq!(f.glyph_index(0x250c), 218); // ┌ upper-left
        assert_eq!(f.glyph_index(0x2510), 191); // ┐ upper-right
        assert_eq!(f.glyph_index(0x2514), 192); // └ lower-left
        assert_eq!(f.glyph_index(0x2518), 217); // ┘ lower-right
        assert_eq!(f.glyph_index(0x253c), 197); // ┼ cross
        assert_eq!(f.glyph_index(0x2592), 177); // ▒ shade
        assert_eq!(f.glyph_index(0x2588), 219); // █ full block
    }

    #[test]
    fn accented_latin_resolves() {
        let f = parse_psf2(DEFAULT_PSF).unwrap();
        assert_eq!(f.glyph_index(0x00e9), 130); // é
        assert_eq!(f.glyph_index(0x00f1), 164); // ñ
    }

    #[test]
    fn unmapped_falls_back_to_question_mark() {
        let f = parse_psf2(DEFAULT_PSF).unwrap();
        // U+25C6 (◆) is not in CP437 → fallback to '?' (glyph 63).
        assert_eq!(f.glyph_index(0x25c6), 63);
        assert_eq!(f.glyph_index(0x1f600), 63); // emoji → '?'
    }

    #[test]
    fn glyph_row_in_range() {
        let f = parse_psf2(DEFAULT_PSF).unwrap();
        // 'A' (glyph 65) has set pixels somewhere in its 16 rows.
        let any = (0..16).any(|py| f.glyph_row(65, py) != 0);
        assert!(any, "'A' glyph must have pixels");
        assert_eq!(f.glyph_row(65, 999), 0, "out-of-range row is blank");
        assert_eq!(f.glyph_row(9999, 0), 0, "out-of-range glyph is blank");
    }
}
