//! Typed decode of the path, region-shape and region-clip ordinals; 31d§1, 53§2.
//! Signed parameters occupy the low 32 bits of a raw argument word.
use super::ordinals::*;
use ipc::win32_gdi::Rect;

fn signed(value: u64) -> i32 { value as u32 as i32 }
fn rect(values: &[u64]) -> Rect { Rect { left: signed(values[0]), top: signed(values[1]), right: signed(values[2]), bottom: signed(values[3]) } }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PathOp { Begin, End, Abort, CloseFigure, Flatten, Widen, Fill, Stroke, StrokeAndFill, ToRegion }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    Path { dc: u64, op: PathOp },
    GetPath { dc: u64, points: u64, types: u64, size: i32 },
    SelectClipPath { dc: u64, mode: i32 },
    CreateEllipticRgn { rect: Rect },
    CreateRoundRectRgn { rect: Rect, ellipse_width: i32, ellipse_height: i32 },
    ExtCreateRegion { xform: u64, count: u32, data: u64 },
    EqualRgn { first: u64, second: u64 },
    OffsetRgn { region: u64, x: i32, y: i32 },
    PtInRegion { region: u64, x: i32, y: i32 },
    RectInRegion { region: u64, rect: u64 },
    GetRegionData { region: u64, count: u32, data: u64 },
    ExcludeClipRect { dc: u64, rect: Rect },
    ExtSelectClipRgn { dc: u64, region: u64, mode: i32 },
    OffsetClipRgn { dc: u64, x: i32, y: i32 },
    PtVisible { dc: u64, x: i32, y: i32 },
    GetRandomRgn { dc: u64, region: u64, code: i32 },
    SetMetaRgn { dc: u64 },
    FillRgn { dc: u64, region: u64, brush: u64 },
    FrameRgn { dc: u64, region: u64, brush: u64, width: i32, height: i32 },
    InvertRgn { dc: u64, region: u64 },
}

/// Route only admitted signatures; a short argument slice is never read past. # C: O(log(admitted ordinals))
pub(crate) fn decode(ordinal: u64, args: &[u64]) -> Option<Operation> {
    if args.len() < argument_count(ordinal)? { return None; }
    let path = |op| Operation::Path { dc: args[0], op };
    Some(match ordinal {
        BEGIN_PATH => path(PathOp::Begin),
        END_PATH => path(PathOp::End),
        ABORT_PATH => path(PathOp::Abort),
        CLOSE_FIGURE => path(PathOp::CloseFigure),
        FLATTEN_PATH => path(PathOp::Flatten),
        WIDEN_PATH => path(PathOp::Widen),
        FILL_PATH => path(PathOp::Fill),
        STROKE_PATH => path(PathOp::Stroke),
        STROKE_AND_FILL_PATH => path(PathOp::StrokeAndFill),
        PATH_TO_REGION => path(PathOp::ToRegion),
        GET_PATH => Operation::GetPath { dc: args[0], points: args[1], types: args[2], size: signed(args[3]) },
        SELECT_CLIP_PATH => Operation::SelectClipPath { dc: args[0], mode: signed(args[1]) },
        CREATE_ELLIPTIC_RGN => Operation::CreateEllipticRgn { rect: rect(&args[0..4]) },
        CREATE_ROUND_RECT_RGN => Operation::CreateRoundRectRgn { rect: rect(&args[0..4]),
            ellipse_width: signed(args[4]), ellipse_height: signed(args[5]) },
        EXT_CREATE_REGION => Operation::ExtCreateRegion { xform: args[0], count: args[1] as u32, data: args[2] },
        EQUAL_RGN => Operation::EqualRgn { first: args[0], second: args[1] },
        OFFSET_RGN => Operation::OffsetRgn { region: args[0], x: signed(args[1]), y: signed(args[2]) },
        PT_IN_REGION => Operation::PtInRegion { region: args[0], x: signed(args[1]), y: signed(args[2]) },
        RECT_IN_REGION => Operation::RectInRegion { region: args[0], rect: args[1] },
        GET_REGION_DATA => Operation::GetRegionData { region: args[0], count: args[1] as u32, data: args[2] },
        EXCLUDE_CLIP_RECT => Operation::ExcludeClipRect { dc: args[0], rect: rect(&args[1..5]) },
        EXT_SELECT_CLIP_RGN => Operation::ExtSelectClipRgn { dc: args[0], region: args[1], mode: signed(args[2]) },
        OFFSET_CLIP_RGN => Operation::OffsetClipRgn { dc: args[0], x: signed(args[1]), y: signed(args[2]) },
        PT_VISIBLE => Operation::PtVisible { dc: args[0], x: signed(args[1]), y: signed(args[2]) },
        GET_RANDOM_RGN => Operation::GetRandomRgn { dc: args[0], region: args[1], code: signed(args[2]) },
        SET_META_RGN => Operation::SetMetaRgn { dc: args[0] },
        FILL_RGN => Operation::FillRgn { dc: args[0], region: args[1], brush: args[2] },
        FRAME_RGN => Operation::FrameRgn { dc: args[0], region: args[1], brush: args[2],
            width: signed(args[3]), height: signed(args[4]) },
        INVERT_RGN => Operation::InvertRgn { dc: args[0], region: args[1] },
        _ => return None,
    })
}

#[cfg(test)]
#[path = "../tests/gdi_shape_decode.rs"]
mod tests;
