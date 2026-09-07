//! Ordinal table and typed decode for the bitmap, blit and palette calls.
//! Windows scalars are 32 bits wide; register halves above them are the
//! caller's and are never read.

pub const ALPHA_BLEND: u64 = 0x108c;
pub const BIT_BLT: u64 = 0x1097;
pub const CREATE_COMPATIBLE_BITMAP: u64 = 0x10ad;
pub const CREATE_DIB_BRUSH: u64 = 0x10af;
pub const CREATE_DIB_SECTION: u64 = 0x10b0;
pub const CREATE_DIBITMAP: u64 = 0x10b1;
pub const CREATE_HALFTONE_PALETTE: u64 = 0x10b3;
pub const CREATE_HATCH_BRUSH: u64 = 0x10b4;
pub const CREATE_PALETTE: u64 = 0x10b8;
pub const DO_PALETTE: u64 = 0x1195;
pub const DRAW_STREAM: u64 = 0x1197;
pub const EXT_FLOOD_FILL: u64 = 0x11c6;
pub const GET_BITMAP_BITS: u64 = 0x11dd;
pub const GET_BITMAP_DIMENSION: u64 = 0x11de;
pub const GET_DIBITS: u64 = 0x11f3;
pub const GET_NEAREST_COLOR: u64 = 0x120b;
pub const GET_NEAREST_PALETTE_INDEX: u64 = 0x120c;
pub const GET_PIXEL: u64 = 0x1217;
pub const GET_SYSTEM_PALETTE_USE: u64 = 0x1224;
pub const GRADIENT_FILL: u64 = 0x122e;
pub const ICM_BRUSH_INFO: u64 = 0x1234;
pub const MASK_BLT: u64 = 0x123f;
pub const PLG_BLT: u64 = 0x124e;
pub const RESIZE_PALETTE: u64 = 0x125e;
pub const SELECT_BITMAP: u64 = 0x126b;
pub const SET_BITMAP_BITS: u64 = 0x1271;
pub const SET_BITMAP_DIMENSION: u64 = 0x1272;
pub const SET_DIBITS_TO_DEVICE: u64 = 0x1278;
pub const SET_MAGIC_COLORS: u64 = 0x127f;
pub const SET_PIXEL: u64 = 0x1284;
pub const SET_SYSTEM_PALETTE_USE: u64 = 0x1289;
pub const STRETCH_BLT: u64 = 0x128f;
pub const STRETCH_DIBITS: u64 = 0x1290;
pub const TRANSPARENT_BLT: u64 = 0x1295;
pub const UNREALIZE_OBJECT: u64 = 0x1299;
pub const UPDATE_COLORS: u64 = 0x129a;
pub const REALIZE_PALETTE: u64 = 0x14e4;
pub const SELECT_PALETTE: u64 = 0x152c;

/// Widest logical signature in this family; test-only bound (gdi_bitmap_raw/tests.rs).
#[cfg(test)]
pub const MAX_ARGUMENTS: usize = 16;

/// Ordinal and its logical parameter count, sorted for binary search.
pub const ORDINALS: &[(u64, usize)] = &[
    (ALPHA_BLEND, 12), (BIT_BLT, 11), (CREATE_COMPATIBLE_BITMAP, 3), (CREATE_DIB_BRUSH, 6),
    (CREATE_DIB_SECTION, 9), (CREATE_DIBITMAP, 11), (CREATE_HALFTONE_PALETTE, 1), (CREATE_HATCH_BRUSH, 3),
    (CREATE_PALETTE, 2), (DO_PALETTE, 6), (DRAW_STREAM, 3), (EXT_FLOOD_FILL, 5), (GET_BITMAP_BITS, 3),
    (GET_BITMAP_DIMENSION, 2), (GET_DIBITS, 9), (GET_NEAREST_COLOR, 2), (GET_NEAREST_PALETTE_INDEX, 2),
    (GET_PIXEL, 3), (GET_SYSTEM_PALETTE_USE, 1), (GRADIENT_FILL, 6), (ICM_BRUSH_INFO, 8), (MASK_BLT, 13),
    (PLG_BLT, 11), (RESIZE_PALETTE, 2), (SELECT_BITMAP, 2), (SET_BITMAP_BITS, 3), (SET_BITMAP_DIMENSION, 4),
    (SET_DIBITS_TO_DEVICE, 16), (SET_MAGIC_COLORS, 3), (SET_PIXEL, 4), (SET_SYSTEM_PALETTE_USE, 2),
    (STRETCH_BLT, 12), (STRETCH_DIBITS, 16), (TRANSPARENT_BLT, 11), (UNREALIZE_OBJECT, 1),
    (UPDATE_COLORS, 1), (REALIZE_PALETTE, 1), (SELECT_PALETTE, 3),
];

/// # C: O(log(number of admitted ordinals))
pub fn argument_count(ordinal: u64) -> Option<usize> {
    ORDINALS.binary_search_by_key(&ordinal, |entry| entry.0).ok().map(|index| ORDINALS[index].1)
}

/// One destination or source rectangle in Windows parameter order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rect { pub x: i32, pub y: i32, pub width: i32, pub height: i32 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    CreateCompatibleBitmap { dc: u64, width: i32, height: i32 },
    CreateDibSection { dc: u64, section: u64, info: u64, usage: u32, bits_out: u64 },
    CreateDibitmap { dc: u64, width: i32, height: i32, init: u32, bits: u64, info: u64, usage: u32 },
    CreateDibBrush { data: u64, usage: u32 },
    CreateHatchBrush { style: u32, color: u32 },
    CreatePalette { logpalette: u64, count: u32 },
    CreateHalftonePalette,
    DoPalette { handle: u64, start: u32, count: u32, entries: u64, function: u32, inbound: bool },
    ResizePalette { palette: u64, count: u32 },
    GetNearestColor { dc: u64, color: u32 },
    GetNearestPaletteIndex { palette: u64, color: u32 },
    GetSystemPaletteUse,
    SetSystemPaletteUse { value: u32 },
    UnrealizeObject { handle: u64 },
    UpdateColors { dc: u64 },
    SelectPalette { dc: u64, palette: u64, background: bool },
    RealizePalette { dc: u64 },
    SelectBitmap { dc: u64, bitmap: u64 },
    GetBitmapBits { bitmap: u64, count: i64, bits: u64 },
    SetBitmapBits { bitmap: u64, count: i64, bits: u64 },
    GetBitmapDimension { bitmap: u64, size: u64 },
    SetBitmapDimension { bitmap: u64, x: i32, y: i32, previous: u64 },
    GetDiBits { dc: u64, bitmap: u64, start: u32, lines: u32, bits: u64, info: u64, usage: u32 },
    SetDiBitsToDevice { dc: u64, dst: Rect, src_x: i32, src_y: i32, start: u32, lines: u32, bits: u64, info: u64, usage: u32 },
    StretchDiBits { dc: u64, dst: Rect, src: Rect, bits: u64, info: u64, usage: u32, code: u32 },
    BitBlt { dst: u64, dst_rect: Rect, src: u64, src_x: i32, src_y: i32, code: u32 },
    StretchBlt { dst: u64, dst_rect: Rect, src: u64, src_rect: Rect, code: u32 },
    MaskBlt { dst: u64, dst_rect: Rect, src: u64, src_x: i32, src_y: i32, mask: u64, mask_x: i32, mask_y: i32, code: u32 },
    PlgBlt { dst: u64, points: u64, src: u64, src_x: i32, src_y: i32, width: i32, height: i32, mask: u64, mask_x: i32, mask_y: i32 },
    TransparentBlt { dst: u64, dst_rect: Rect, src: u64, src_rect: Rect, transparent: u32 },
    AlphaBlend { dst: u64, dst_rect: Rect, src: u64, src_rect: Rect, blend: u32 },
    GradientFill { dc: u64, vertices: u64, vertex_count: u32, indexes: u64, shape_count: u32, mode: u32 },
    GetPixel { dc: u64, x: i32, y: i32 },
    SetPixel { dc: u64, x: i32, y: i32, color: u32 },
    ExtFloodFill { dc: u64, x: i32, y: i32, color: u32, kind: u32 },
    IcmBrushInfo { brush: u64, info: u64, bits: u64, bits_size: u64, usage: u64, mode: u32 },
    DrawStream,
    SetMagicColors,
}

fn scalar(args: &[u64], index: usize) -> i32 { args[index] as u32 as i32 }
fn dword(args: &[u64], index: usize) -> u32 { args[index] as u32 }
fn rect(args: &[u64], at: usize) -> Rect {
    Rect { x: scalar(args, at), y: scalar(args, at + 1), width: scalar(args, at + 2), height: scalar(args, at + 3) }
}

/// Decode one admitted ordinal from its complete logical argument list.
/// # C: O(1)
pub fn decode(ordinal: u64, args: &[u64]) -> Option<Operation> {
    if args.len() < argument_count(ordinal)? { return None; }
    Some(match ordinal {
        CREATE_COMPATIBLE_BITMAP => Operation::CreateCompatibleBitmap { dc: args[0], width: scalar(args, 1), height: scalar(args, 2) },
        CREATE_DIB_SECTION => Operation::CreateDibSection { dc: args[0], section: args[1], info: args[3], usage: dword(args, 4), bits_out: args[8] },
        CREATE_DIBITMAP => Operation::CreateDibitmap { dc: args[0], width: scalar(args, 1), height: scalar(args, 2),
            init: dword(args, 3), bits: args[4], info: args[5], usage: dword(args, 6) },
        CREATE_DIB_BRUSH => Operation::CreateDibBrush { data: args[0], usage: dword(args, 1) },
        CREATE_HATCH_BRUSH => Operation::CreateHatchBrush { style: dword(args, 0), color: dword(args, 1) },
        CREATE_PALETTE => Operation::CreatePalette { logpalette: args[0], count: dword(args, 1) },
        CREATE_HALFTONE_PALETTE => Operation::CreateHalftonePalette,
        DO_PALETTE => Operation::DoPalette { handle: args[0], start: args[1] as u16 as u32, count: args[2] as u16 as u32,
            entries: args[3], function: dword(args, 4), inbound: dword(args, 5) != 0 },
        RESIZE_PALETTE => Operation::ResizePalette { palette: args[0], count: dword(args, 1) },
        GET_NEAREST_COLOR => Operation::GetNearestColor { dc: args[0], color: dword(args, 1) },
        GET_NEAREST_PALETTE_INDEX => Operation::GetNearestPaletteIndex { palette: args[0], color: dword(args, 1) },
        GET_SYSTEM_PALETTE_USE => Operation::GetSystemPaletteUse,
        SET_SYSTEM_PALETTE_USE => Operation::SetSystemPaletteUse { value: dword(args, 1) },
        UNREALIZE_OBJECT => Operation::UnrealizeObject { handle: args[0] },
        UPDATE_COLORS => Operation::UpdateColors { dc: args[0] },
        SELECT_PALETTE => Operation::SelectPalette { dc: args[0], palette: args[1], background: args[2] as u16 != 0 },
        REALIZE_PALETTE => Operation::RealizePalette { dc: args[0] },
        SELECT_BITMAP => Operation::SelectBitmap { dc: args[0], bitmap: args[1] },
        GET_BITMAP_BITS => Operation::GetBitmapBits { bitmap: args[0], count: i64::from(scalar(args, 1)), bits: args[2] },
        SET_BITMAP_BITS => Operation::SetBitmapBits { bitmap: args[0], count: i64::from(scalar(args, 1)), bits: args[2] },
        GET_BITMAP_DIMENSION => Operation::GetBitmapDimension { bitmap: args[0], size: args[1] },
        SET_BITMAP_DIMENSION => Operation::SetBitmapDimension { bitmap: args[0], x: scalar(args, 1), y: scalar(args, 2), previous: args[3] },
        GET_DIBITS => Operation::GetDiBits { dc: args[0], bitmap: args[1], start: dword(args, 2), lines: dword(args, 3),
            bits: args[4], info: args[5], usage: dword(args, 6) },
        SET_DIBITS_TO_DEVICE => Operation::SetDiBitsToDevice { dc: args[0],
            dst: Rect { x: scalar(args, 1), y: scalar(args, 2), width: scalar(args, 3), height: scalar(args, 4) },
            src_x: scalar(args, 5), src_y: scalar(args, 6), start: dword(args, 7), lines: dword(args, 8),
            bits: args[9], info: args[10], usage: dword(args, 11) },
        STRETCH_DIBITS => Operation::StretchDiBits { dc: args[0], dst: rect(args, 1), src: rect(args, 5),
            bits: args[9], info: args[10], usage: dword(args, 11), code: dword(args, 12) },
        BIT_BLT => Operation::BitBlt { dst: args[0], dst_rect: rect(args, 1), src: args[5],
            src_x: scalar(args, 6), src_y: scalar(args, 7), code: dword(args, 8) },
        STRETCH_BLT => Operation::StretchBlt { dst: args[0], dst_rect: rect(args, 1), src: args[5], src_rect: rect(args, 6), code: dword(args, 10) },
        MASK_BLT => Operation::MaskBlt { dst: args[0], dst_rect: rect(args, 1), src: args[5], src_x: scalar(args, 6),
            src_y: scalar(args, 7), mask: args[8], mask_x: scalar(args, 9), mask_y: scalar(args, 10), code: dword(args, 11) },
        PLG_BLT => Operation::PlgBlt { dst: args[0], points: args[1], src: args[2], src_x: scalar(args, 3), src_y: scalar(args, 4),
            width: scalar(args, 5), height: scalar(args, 6), mask: args[7], mask_x: scalar(args, 8), mask_y: scalar(args, 9) },
        TRANSPARENT_BLT => Operation::TransparentBlt { dst: args[0], dst_rect: rect(args, 1), src: args[5],
            src_rect: rect(args, 6), transparent: dword(args, 10) },
        ALPHA_BLEND => Operation::AlphaBlend { dst: args[0], dst_rect: rect(args, 1), src: args[5], src_rect: rect(args, 6), blend: dword(args, 10) },
        GRADIENT_FILL => Operation::GradientFill { dc: args[0], vertices: args[1], vertex_count: dword(args, 2),
            indexes: args[3], shape_count: dword(args, 4), mode: dword(args, 5) },
        GET_PIXEL => Operation::GetPixel { dc: args[0], x: scalar(args, 1), y: scalar(args, 2) },
        SET_PIXEL => Operation::SetPixel { dc: args[0], x: scalar(args, 1), y: scalar(args, 2), color: dword(args, 3) },
        EXT_FLOOD_FILL => Operation::ExtFloodFill { dc: args[0], x: scalar(args, 1), y: scalar(args, 2), color: dword(args, 3), kind: dword(args, 4) },
        ICM_BRUSH_INFO => Operation::IcmBrushInfo { brush: args[1], info: args[2], bits: args[3], bits_size: args[4],
            usage: args[5], mode: dword(args, 7) },
        DRAW_STREAM => Operation::DrawStream,
        SET_MAGIC_COLORS => Operation::SetMagicColors,
        _ => return None,
    })
}

#[cfg(test)]
#[path = "gdi_bitmap_raw/tests.rs"]
mod tests;
