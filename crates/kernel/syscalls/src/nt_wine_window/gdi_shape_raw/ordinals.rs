//! Admitted win32u ordinals for paths, region shapes and region clipping; 31d§1.
pub(crate) const ABORT_PATH: u64 = 0x1085;
pub(crate) const BEGIN_PATH: u64 = 0x1096;
pub(crate) const CLOSE_FIGURE: u64 = 0x10a0;
pub(crate) const CREATE_ELLIPTIC_RGN: u64 = 0x10b2;
pub(crate) const CREATE_ROUND_RECT_RGN: u64 = 0x10bc;
pub(crate) const END_PATH: u64 = 0x119e;
pub(crate) const EQUAL_RGN: u64 = 0x11c0;
pub(crate) const EXCLUDE_CLIP_RECT: u64 = 0x11c2;
pub(crate) const EXT_CREATE_REGION: u64 = 0x11c4;
pub(crate) const EXT_SELECT_CLIP_RGN: u64 = 0x11c8;
pub(crate) const FILL_PATH: u64 = 0x11d2;
pub(crate) const FILL_RGN: u64 = 0x11d3;
pub(crate) const FLATTEN_PATH: u64 = 0x11d4;
pub(crate) const FRAME_RGN: u64 = 0x11d8;
pub(crate) const GET_PATH: u64 = 0x1212;
pub(crate) const GET_RANDOM_RGN: u64 = 0x121a;
pub(crate) const GET_REGION_DATA: u64 = 0x121d;
pub(crate) const INVERT_RGN: u64 = 0x1239;
pub(crate) const OFFSET_CLIP_RGN: u64 = 0x1244;
pub(crate) const OFFSET_RGN: u64 = 0x1245;
pub(crate) const PATH_TO_REGION: u64 = 0x124d;
pub(crate) const PT_IN_REGION: u64 = 0x1253;
pub(crate) const PT_VISIBLE: u64 = 0x1254;
pub(crate) const RECT_IN_REGION: u64 = 0x1257;
pub(crate) const SELECT_CLIP_PATH: u64 = 0x126d;
pub(crate) const SET_META_RGN: u64 = 0x1280;
pub(crate) const STROKE_AND_FILL_PATH: u64 = 0x1291;
pub(crate) const STROKE_PATH: u64 = 0x1292;
pub(crate) const WIDEN_PATH: u64 = 0x129d;

/// Logical parameter counts in Windows order, sorted by ordinal for lookup.
const COUNTS: &[(u64, usize)] = &[
    (ABORT_PATH, 1), (BEGIN_PATH, 1), (CLOSE_FIGURE, 1), (CREATE_ELLIPTIC_RGN, 4),
    (CREATE_ROUND_RECT_RGN, 6), (END_PATH, 1), (EQUAL_RGN, 2), (EXCLUDE_CLIP_RECT, 5),
    (EXT_CREATE_REGION, 3), (EXT_SELECT_CLIP_RGN, 3), (FILL_PATH, 1), (FILL_RGN, 3),
    (FLATTEN_PATH, 1), (FRAME_RGN, 5), (GET_PATH, 4), (GET_RANDOM_RGN, 3),
    (GET_REGION_DATA, 3), (INVERT_RGN, 2), (OFFSET_CLIP_RGN, 3), (OFFSET_RGN, 3),
    (PATH_TO_REGION, 1), (PT_IN_REGION, 3), (PT_VISIBLE, 3), (RECT_IN_REGION, 2),
    (SELECT_CLIP_PATH, 2), (SET_META_RGN, 1), (STROKE_AND_FILL_PATH, 1), (STROKE_PATH, 1),
    (WIDEN_PATH, 1),
];

/// # C: O(log(number of admitted ordinals))
pub(crate) fn argument_count(ordinal: u64) -> Option<usize> {
    COUNTS.binary_search_by_key(&ordinal, |entry| entry.0).ok().map(|index| COUNTS[index].1)
}

#[cfg(test)]
#[path = "../tests/gdi_shape_ordinals.rs"]
mod tests;
