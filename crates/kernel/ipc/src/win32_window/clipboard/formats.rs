//! Standard clipboard format identifiers and the close-time synthesis table.

pub const CF_TEXT: u32 = 1;
pub const CF_BITMAP: u32 = 2;
pub const CF_METAFILEPICT: u32 = 3;
pub const CF_OEMTEXT: u32 = 7;
pub const CF_DIB: u32 = 8;
pub const CF_PALETTE: u32 = 9;
pub const CF_UNICODETEXT: u32 = 13;
pub const CF_ENHMETAFILE: u32 = 14;
pub const CF_LOCALE: u32 = 16;
pub const CF_DIBV5: u32 = 17;
/// One past the last format the existence bitmap tracks.
pub const CF_MAX: u32 = 18;

/// Each row is `[target, first source, second source]`; a zero source slot is
/// absent. On close, a target the store lacks is added as a delay-rendered
/// entry naming whichever source is present, so a text-only owner still
/// answers the other text formats.
pub const SYNTHESIS: [[u32; 3]; 8] = [
    [CF_TEXT, CF_OEMTEXT, CF_UNICODETEXT],
    [CF_OEMTEXT, CF_UNICODETEXT, CF_TEXT],
    [CF_UNICODETEXT, CF_TEXT, CF_OEMTEXT],
    [CF_METAFILEPICT, CF_ENHMETAFILE, 0],
    [CF_ENHMETAFILE, CF_METAFILEPICT, 0],
    [CF_BITMAP, CF_DIB, CF_DIBV5],
    [CF_DIB, CF_BITMAP, CF_DIBV5],
    [CF_DIBV5, CF_BITMAP, CF_DIB],
];
