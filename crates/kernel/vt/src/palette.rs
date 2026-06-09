// Canonical VT color palette (Linux/xterm). vtdata owns this so the SGR
// emulator resolves 16/256-color indices to 24-bit RGB AT SET-TIME and
// stores resolved RGB in each `Cell`. Downstream renderers (fbcon) read
// `cell.fg`/`cell.bg` RGB directly — no per-cell palette lookup.

/// VGA 16-color palette: index → [r,g,b]. Indices 0..7 = normal,
/// 8..15 = bright. Matches the classic VGA/Linux console colors.
/// # C: const.
pub const VGA_PALETTE: [[u8; 3]; 16] = [
    [0x00, 0x00, 0x00], [0xaa, 0x00, 0x00], [0x00, 0xaa, 0x00], [0xaa, 0x55, 0x00],
    [0x00, 0x00, 0xaa], [0xaa, 0x00, 0xaa], [0x00, 0xaa, 0xaa], [0xaa, 0xaa, 0xaa],
    [0x55, 0x55, 0x55], [0xff, 0x55, 0x55], [0x55, 0xff, 0x55], [0xff, 0xff, 0x55],
    [0x55, 0x55, 0xff], [0xff, 0x55, 0xff], [0x55, 0xff, 0xff], [0xff, 0xff, 0xff],
];

/// Pack an [r,g,b] triple into a 0x00RRGGBB pixel.
/// # C: O(1).
#[inline]
pub fn rgb(c: [u8; 3]) -> u32 {
    ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | (c[2] as u32)
}

/// Resolve an SGR 256-color index to 0x00RRGGBB per xterm.
/// 0..15 = VGA palette; 16..231 = 6×6×6 cube; 232..255 = grayscale ramp.
/// Out-of-range (>=256) clamps to 255. # C: O(1).
pub fn xterm_256_rgb(idx: u32) -> u32 {
    rgb(xterm_256(idx))
}

/// Resolve an SGR 256-color index to [r,g,b] per xterm (see `xterm_256_rgb`).
/// # C: O(1).
pub fn xterm_256(idx: u32) -> [u8; 3] {
    if idx < 16 {
        return VGA_PALETTE[idx as usize];
    }
    if idx < 232 {
        let i = idx - 16;
        let r = (i / 36) as u8;
        let g = ((i / 6) % 6) as u8;
        let b = (i % 6) as u8;
        let level = |x: u8| if x == 0 { 0u8 } else { 55 + 40 * x };
        return [level(r), level(g), level(b)];
    }
    let idx = idx.min(255);
    let g = 8u8 + 10u8 * ((idx - 232) as u8);
    [g, g, g]
}
