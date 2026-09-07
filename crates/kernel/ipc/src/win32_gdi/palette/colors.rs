//! Default colour tables for the indexed bitmap depths; 31fk§4.
//! Entries are (red, green, blue).

/// The twenty static system colours: the eight-bit table's first and last ten.
const SYSTEM_HEAD: [(u8, u8, u8); 10] = [
    (0x00, 0x00, 0x00), (0x80, 0x00, 0x00), (0x00, 0x80, 0x00), (0x80, 0x80, 0x00), (0x00, 0x00, 0x80),
    (0x80, 0x00, 0x80), (0x00, 0x80, 0x80), (0xc0, 0xc0, 0xc0), (0xc0, 0xdc, 0xc0), (0xa6, 0xca, 0xf0),
];
const SYSTEM_TAIL: [(u8, u8, u8); 10] = [
    (0xff, 0xfb, 0xf0), (0xa0, 0xa0, 0xa4), (0x80, 0x80, 0x80), (0xff, 0x00, 0x00), (0x00, 0xff, 0x00),
    (0xff, 0xff, 0x00), (0x00, 0x00, 0xff), (0xff, 0x00, 0xff), (0x00, 0xff, 0xff), (0xff, 0xff, 0xff),
];
/// The sixteen-entry table used at four bits per pixel.
const TABLE_4: [(u8, u8, u8); 16] = [
    (0x00, 0x00, 0x00), (0x80, 0x00, 0x00), (0x00, 0x80, 0x00), (0x80, 0x80, 0x00),
    (0x00, 0x00, 0x80), (0x80, 0x00, 0x80), (0x00, 0x80, 0x80), (0x80, 0x80, 0x80),
    (0xc0, 0xc0, 0xc0), (0xff, 0x00, 0x00), (0x00, 0xff, 0x00), (0xff, 0xff, 0x00),
    (0x00, 0x00, 0xff), (0xff, 0x00, 0xff), (0x00, 0xff, 0xff), (0xff, 0xff, 0xff),
];
/// Monochrome resolves index zero to black and index one to white.
const TABLE_1: [(u8, u8, u8); 2] = [(0x00, 0x00, 0x00), (0xff, 0xff, 0xff)];
/// Eight-bit entries between the two system blocks span a blue-major colour
/// cube: four blue levels, eight green levels, eight red levels.
const CUBE_BASE: u32 = 10;
const CUBE_END: u32 = 246;
const BLUE_STEP: u32 = 0x40;
const CHANNEL_STEP: u32 = 0x20;
const GREEN_LEVELS: u32 = 8;
const RED_LEVELS: u32 = 8;

/// Entry count of the default table for one depth; deeper depths have none. # C: O(1)
pub fn default_color_table_len(bpp: u32) -> Option<u32> {
    match bpp { 1 => Some(TABLE_1.len() as u32), 4 => Some(TABLE_4.len() as u32), 8 => Some(256), _ => None }
}

/// One default colour-table entry as (red, green, blue). # C: O(1)
pub fn default_color_entry(bpp: u32, index: u32) -> Option<(u8, u8, u8)> {
    if index >= default_color_table_len(bpp)? { return None; }
    Some(match bpp {
        1 => TABLE_1[index as usize],
        4 => TABLE_4[index as usize],
        _ if index < CUBE_BASE => SYSTEM_HEAD[index as usize],
        _ if index >= CUBE_END => SYSTEM_TAIL[(index - CUBE_END) as usize],
        _ => {
            let blue = (index / (GREEN_LEVELS * RED_LEVELS)) * BLUE_STEP;
            let green = ((index / RED_LEVELS) % GREEN_LEVELS) * CHANNEL_STEP;
            let red = (index % RED_LEVELS) * CHANNEL_STEP;
            (red as u8, green as u8, blue as u8)
        }
    })
}

#[cfg(test)]
#[path = "../tests/palette_colors.rs"]
mod tests;
