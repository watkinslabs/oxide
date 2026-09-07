//! Pixel access at every stored bitmap depth; 31fk§4.
//! Indexed depths resolve through a colour table, direct depths through their
//! channel masks. Reads answer XRGB; writes take XRGB and encode.
use alloc::vec::Vec;

/// One colour-table entry. The stored fourth byte carries no colour.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rgb { pub red: u8, pub green: u8, pub blue: u8 }

impl Rgb {
    /// # C: O(1)
    pub fn xrgb(&self) -> u32 { (u32::from(self.red) << 16) | (u32::from(self.green) << 8) | u32::from(self.blue) }
    /// # C: O(1)
    pub fn from_xrgb(value: u32) -> Self { Self { red: (value >> 16) as u8, green: (value >> 8) as u8, blue: value as u8 } }
}

/// Default sixteen-bit channel masks when the header names no bitfields.
pub const DEFAULT_555: [u32; 3] = [0x7c00, 0x03e0, 0x001f];
/// Default twenty-four and thirty-two bit channel masks.
pub const DEFAULT_888: [u32; 3] = [0x00ff_0000, 0x0000_ff00, 0x0000_00ff];
const BITS_PER_BYTE: u32 = 8;
const NIBBLE_BITS: u32 = 4;

/// Depths that address a colour table rather than carrying channels. # C: O(1)
pub fn is_indexed(bpp: u32) -> bool { matches!(bpp, 1 | 4 | 8) }

fn row_at(stride: i32, y: i32) -> Option<usize> {
    if y < 0 || stride < 0 { return None; }
    (y as usize).checked_mul(stride as usize)
}

/// Raw stored value of one pixel: a colour-table index at indexed depths, the
/// packed channel word otherwise. # C: O(1)
pub fn raw_pixel(bits: &[u8], stride: i32, bpp: u32, x: i32, y: i32) -> Option<u32> {
    if x < 0 { return None; }
    let row = row_at(stride, y)?;
    let x = x as usize;
    Some(match bpp {
        1 => u32::from((bits.get(row + x / 8)? >> (7 - (x % 8))) & 1),
        4 => { let byte = *bits.get(row + x / 2)?; u32::from(if x % 2 == 0 { byte >> NIBBLE_BITS } else { byte & 0x0f }) }
        8 => u32::from(*bits.get(row + x)?),
        16 => u32::from(u16::from_le_bytes([*bits.get(row + x * 2)?, *bits.get(row + x * 2 + 1)?])),
        24 => { let at = row + x * 3;
            u32::from(*bits.get(at)?) | (u32::from(*bits.get(at + 1)?) << 8) | (u32::from(*bits.get(at + 2)?) << 16) }
        32 => { let at = row + x * 4;
            u32::from_le_bytes([*bits.get(at)?, *bits.get(at + 1)?, *bits.get(at + 2)?, *bits.get(at + 3)?]) }
        _ => return None,
    })
}

/// Store one raw pixel value, leaving neighbouring pixels of a sub-byte depth
/// untouched. # C: O(1)
pub fn put_raw_pixel(bits: &mut [u8], stride: i32, bpp: u32, x: i32, y: i32, value: u32) -> Option<()> {
    if x < 0 { return None; }
    let row = row_at(stride, y)?;
    let x = x as usize;
    match bpp {
        1 => { let byte = bits.get_mut(row + x / 8)?; let mask = 1u8 << (7 - (x % 8));
            if value & 1 != 0 { *byte |= mask; } else { *byte &= !mask; } }
        4 => { let byte = bits.get_mut(row + x / 2)?; let value = (value & 0x0f) as u8;
            if x % 2 == 0 { *byte = (*byte & 0x0f) | (value << NIBBLE_BITS); } else { *byte = (*byte & 0xf0) | value; } }
        8 => *bits.get_mut(row + x)? = value as u8,
        16 => { let at = row + x * 2; if at + 1 >= bits.len() { return None; }
            bits[at..at + 2].copy_from_slice(&(value as u16).to_le_bytes()); }
        24 => { let at = row + x * 3; if at + 2 >= bits.len() { return None; }
            bits[at] = value as u8; bits[at + 1] = (value >> 8) as u8; bits[at + 2] = (value >> 16) as u8; }
        32 => { let at = row + x * 4; if at + 3 >= bits.len() { return None; }
            bits[at..at + 4].copy_from_slice(&value.to_le_bytes()); }
        _ => return None,
    }
    Some(())
}

fn field(mask: u32) -> (u32, u32) {
    if mask == 0 { return (0, 0); }
    let shift = mask.trailing_zeros();
    (shift, (mask >> shift).count_ones())
}

/// Expand one channel to eight bits by replicating its high bits downwards,
/// which keeps an all-ones field at full intensity. # C: O(1)
fn expand(value: u32, width: u32) -> u32 {
    if width == 0 { return 0; }
    if width >= BITS_PER_BYTE { return (value >> (width - BITS_PER_BYTE)) & 0xff; }
    let scaled = (value << (BITS_PER_BYTE - width)) & 0xff;
    scaled | (scaled >> width)
}

/// Decode a packed channel word to XRGB using the depth's masks. # C: O(1)
pub fn masked_to_xrgb(raw: u32, masks: [u32; 3]) -> u32 {
    let mut out = 0;
    for (index, mask) in masks.iter().enumerate() {
        let (shift, width) = field(*mask);
        out |= expand((raw & mask) >> shift, width) << (16 - 8 * index as u32);
    }
    out
}

/// Encode XRGB into a packed channel word using the depth's masks. # C: O(1)
pub fn xrgb_to_masked(color: u32, masks: [u32; 3]) -> u32 {
    let mut out = 0;
    for (index, mask) in masks.iter().enumerate() {
        let (shift, width) = field(*mask);
        if width == 0 { continue; }
        let channel = (color >> (16 - 8 * index as u32)) & 0xff;
        out |= ((channel >> (BITS_PER_BYTE - width.min(BITS_PER_BYTE))) << shift) & mask;
    }
    out
}

/// Nearest colour-table entry by squared channel distance. # C: O(table)
pub fn nearest_index(table: &[Rgb], color: u32) -> u32 {
    let want = Rgb::from_xrgb(color);
    let (mut index, mut best) = (0u32, i32::MAX);
    for (slot, entry) in table.iter().enumerate() {
        let channel = |a: u8, b: u8| i32::from(a) - i32::from(b);
        let (r, g, b) = (channel(entry.red, want.red), channel(entry.green, want.green), channel(entry.blue, want.blue));
        let distance = r * r + g * g + b * b;
        if distance < best { index = slot as u32; best = distance; if best == 0 { break; } }
    }
    index
}

/// Build a colour table of the depth's default length. # C: O(entries)
pub fn default_table(bpp: u32) -> Option<Vec<Rgb>> {
    let len = super::super::palette::default_color_table_len(bpp)?;
    let mut table = Vec::new();
    table.try_reserve_exact(len as usize).ok()?;
    for index in 0..len {
        let (red, green, blue) = super::super::palette::default_color_entry(bpp, index)?;
        table.push(Rgb { red, green, blue });
    }
    Some(table)
}

#[cfg(test)]
#[path = "../tests/bitmap_pixels.rs"]
mod tests;
