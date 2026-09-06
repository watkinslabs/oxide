//! Raw win32u GDI ABI decoding.
//!
//! This module owns no GDI objects and performs no rasterization. It converts
//! the x86-64 Wine ordinal ABI into typed operations for the canonical GDI
//! owner, including the complete nine-argument NtGdiExtTextOutW call.

pub(crate) const CREATE_COMPATIBLE_DC: u64 = 0x10ae;
pub(crate) const DELETE_OBJECT_APP: u64 = 0x118f;
pub(crate) const EXT_TEXT_OUT_W: u64 = 0x11c9;
pub(crate) const GET_SET_DC_DWORD: u64 = 0x11da;
pub(crate) const GET_TEXT_EXTENT_EX_W: u64 = 0x1227;
pub(crate) const GET_TEXT_METRICS_W: u64 = 0x1229;
pub(crate) const HFONT_CREATE: u64 = 0x1233;
pub(crate) const MOVE_TO: u64 = 0x1243;
pub(crate) const SELECT_FONT: u64 = 0x126e;
pub(crate) const TEXT_METRIC_W_BYTES: usize = 60;

pub(crate) const SET_BK_COLOR: u32 = 100;
pub(crate) const SET_BK_MODE: u32 = 101;
pub(crate) const SET_TEXT_COLOR: u32 = 102;
pub(crate) const SET_TEXT_ALIGN: u32 = 107;
pub(crate) const OPAQUE: u32 = 2;
pub(crate) const TA_LEFT_TOP: u32 = 0;
#[path = "gdi_raw/text_output.rs"]
pub(crate) mod text_output;

#[cfg(target_os = "oxide-kernel")]
#[path = "gdi_raw/kernel.rs"]
pub(super) mod kernel;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TextMetricW {
    pub height: i32,
    pub ascent: i32,
    pub descent: i32,
    pub internal_leading: i32,
    pub external_leading: i32,
    pub average_width: i32,
    pub max_width: i32,
    pub weight: i32,
    pub overhang: i32,
    pub digitized_aspect_x: i32,
    pub digitized_aspect_y: i32,
    pub first_char: u16,
    pub last_char: u16,
    pub default_char: u16,
    pub break_char: u16,
    pub italic: u8,
    pub underlined: u8,
    pub struck_out: u8,
    pub pitch_and_family: u8,
    pub charset: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    CreateCompatibleDc { source: u64 },
    DeleteObject { handle: u64 },
    HfontCreate { logfont: u64, size: u32, font_type: u32, flags: u32, data: u64 },
    SelectFont { dc: u64, font: u64 },
    SetDcDword { dc: u64, method: u32, value: u32, previous: u64 },
    MoveTo { dc: u64, x: i32, y: i32, previous: u64 },
    GetTextMetricsW { dc: u64, metrics: u64, flags: u32 },
    GetTextExtentExW { dc: u64, text: u64, count: i32, max_extent: i32, nfit: u64, dx: u64, extent: u64, flags: u32 },
    ExtTextOutW { dc: u64, x: i32, y: i32, flags: u32, rect: u64, text: u64, count: u32, dx: u64, code_page: u32 },
}

fn signed(value: u64) -> i32 { value as u32 as i32 }
fn dword(value: u64) -> u32 { value as u32 }

/// Convert Win32 COLORREF (0x00bbggrr) to the internal XRGB order
/// (0x00rrggbb). Only color fields use this conversion; handles and pointers
/// remain full-width ABI values.
pub(crate) fn colorref_to_xrgb(value: u32) -> u32 {
    ((value & 0xff) << 16) | (value & 0xff00) | ((value >> 16) & 0xff)
}

/// Encode the real 60-byte TEXTMETRICW ABI. The native owner supplies every
/// field; this adapter does not invent a 24-byte facade or silently truncate
/// the output structure.
pub(crate) fn encode_text_metric_w(value: TextMetricW) -> [u8; TEXT_METRIC_W_BYTES] {
    let mut bytes = [0u8; TEXT_METRIC_W_BYTES];
    for (offset, field) in [
        (0, value.height), (4, value.ascent), (8, value.descent),
        (12, value.internal_leading), (16, value.external_leading),
        (20, value.average_width), (24, value.max_width), (28, value.weight),
        (32, value.overhang), (36, value.digitized_aspect_x),
        (40, value.digitized_aspect_y),
    ] { bytes[offset..offset + 4].copy_from_slice(&field.to_le_bytes()); }
    for (offset, field) in [(44, value.first_char), (46, value.last_char), (48, value.default_char), (50, value.break_char)] {
        bytes[offset..offset + 2].copy_from_slice(&field.to_le_bytes());
    }
    bytes[52..57].copy_from_slice(&[value.italic, value.underlined, value.struck_out, value.pitch_and_family, value.charset]);
    bytes
}

/// Decode a complete descriptor-backed call in Windows argument order.
pub(crate) fn decode(ordinal: u64, args: &[u64; 9]) -> Option<Operation> {
    Some(match ordinal {
        CREATE_COMPATIBLE_DC => Operation::CreateCompatibleDc { source: args[0] },
        DELETE_OBJECT_APP => Operation::DeleteObject { handle: args[0] },
        HFONT_CREATE => Operation::HfontCreate { logfont: args[0], size: dword(args[1]), font_type: dword(args[2]), flags: dword(args[3]), data: args[4] },
        SELECT_FONT => Operation::SelectFont { dc: args[0], font: args[1] },
        GET_SET_DC_DWORD => Operation::SetDcDword { dc: args[0], method: dword(args[1]), value: if dword(args[1]) == SET_BK_COLOR || dword(args[1]) == SET_TEXT_COLOR { colorref_to_xrgb(dword(args[2])) } else { dword(args[2]) }, previous: args[3] },
        MOVE_TO => Operation::MoveTo { dc: args[0], x: signed(args[1]), y: signed(args[2]), previous: args[3] },
        GET_TEXT_METRICS_W => Operation::GetTextMetricsW { dc: args[0], metrics: args[1], flags: dword(args[2]) },
        GET_TEXT_EXTENT_EX_W => Operation::GetTextExtentExW { dc: args[0], text: args[1], count: signed(args[2]), max_extent: signed(args[3]), nfit: args[4], dx: args[5], extent: args[6], flags: dword(args[7]) },
        EXT_TEXT_OUT_W => Operation::ExtTextOutW { dc: args[0], x: signed(args[1]), y: signed(args[2]), flags: dword(args[3]), rect: args[4], text: args[5], count: dword(args[6]), dx: args[7], code_page: dword(args[8]) },
        _ => return None,
    })
}

/// Collect the tail of a raw x86-64 call before typed decoding. The first six
/// values are already normalized by the raw entry router; only stack slots
/// six through eight are needed by the longest Notepad GDI operation.
pub(crate) fn collect_raw(first: [u64; 6], mut stack: impl FnMut(usize) -> Option<u64>) -> Option<[u64; 9]> {
    let mut args = [0u64; 9];
    args[..6].copy_from_slice(&first);
    for index in 6..9 { args[index] = stack(index)?; }
    Some(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_text_out_preserves_all_nine_arguments_and_scalar_widths() {
        let args = [0x10001, 0xffff_ffff_ffff_fffe, 0xffff_ffff_8000_0003, 0x8000_0001, 0x2000, 0x3000, 0x1_0000_0002, 0x4000, 0x1_0000_0007];
        assert_eq!(decode(EXT_TEXT_OUT_W, &args), Some(Operation::ExtTextOutW { dc: 0x10001, x: -2, y: i32::MIN + 3, flags: 0x8000_0001, rect: 0x2000, text: 0x3000, count: 2, dx: 0x4000, code_page: 7 }));
    }

    #[test]
    fn raw_collection_rejects_any_missing_ext_text_tail() {
        assert!(collect_raw([1, 2, 3, 4, 5, 6], |index| (index != 7).then_some(index as u64)).is_none());
        assert_eq!(collect_raw([1, 2, 3, 4, 5, 6], |index| Some(index as u64)).unwrap()[8], 8);
    }

    #[test]
    fn pointer_fields_are_not_scalar_truncated() {
        let args = [0x1_0000_0001, 0x2_0000_0002, 3, 4, 5, 0x6_0000_0006, 7, 8, 9];
        assert_eq!(decode(EXT_TEXT_OUT_W, &args), Some(Operation::ExtTextOutW { dc: 0x1_0000_0001, x: 2, y: 3, flags: 4, rect: 5, text: 0x6_0000_0006, count: 7, dx: 8, code_page: 9 }));
    }

    #[test]
    fn dc_attributes_convert_only_colorref_and_preserve_previous_pointer() {
        let args = [7, SET_TEXT_COLOR as u64, 0x0011_2233, 0x1_0000_0044, 0, 0, 0, 0, 0];
        assert_eq!(decode(GET_SET_DC_DWORD, &args), Some(Operation::SetDcDword { dc: 7, method: SET_TEXT_COLOR, value: 0x0033_2211, previous: 0x1_0000_0044 }));
        let args = [7, SET_BK_COLOR as u64, 0x0001_0203, 0x1_0000_0045, 0, 0, 0, 0, 0];
        assert_eq!(decode(GET_SET_DC_DWORD, &args), Some(Operation::SetDcDword { dc: 7, method: SET_BK_COLOR, value: 0x0003_0201, previous: 0x1_0000_0045 }));
        let args = [7, SET_BK_MODE as u64, OPAQUE as u64, 8, 0, 0, 0, 0, 0];
        assert_eq!(decode(GET_SET_DC_DWORD, &args), Some(Operation::SetDcDword { dc: 7, method: SET_BK_MODE, value: OPAQUE, previous: 8 }));
        let args = [7, SET_TEXT_ALIGN as u64, TA_LEFT_TOP as u64, 9, 0, 0, 0, 0, 0];
        assert_eq!(decode(GET_SET_DC_DWORD, &args), Some(Operation::SetDcDword { dc: 7, method: SET_TEXT_ALIGN, value: TA_LEFT_TOP, previous: 9 }));
    }

    #[test]
    fn move_to_preserves_signed_position_and_previous_output_pointer() {
        let args = [7, 0xffff_ffff_ffff_fffd, 0x0000_0002, 0x1_0000_0046, 0, 0, 0, 0, 0];
        assert_eq!(decode(MOVE_TO, &args), Some(Operation::MoveTo { dc: 7, x: -3, y: 2, previous: 0x1_0000_0046 }));
    }

    #[test]
    fn required_text_defaults_are_explicit_and_metric_abi_is_sixty_bytes() {
        assert_eq!(OPAQUE, 2);
        assert_eq!(TA_LEFT_TOP, 0);
        assert_eq!(TEXT_METRIC_W_BYTES, 60);
    }

    #[test]
    fn text_metric_serializer_writes_real_60_byte_layout() {
        let bytes = encode_text_metric_w(TextMetricW { height: 16, ascent: 12, descent: 4, internal_leading: 1, external_leading: 2, average_width: 8, max_width: 9, weight: 400, overhang: 0, digitized_aspect_x: 96, digitized_aspect_y: 96, first_char: 32, last_char: 0xffff, default_char: 63, break_char: 32, italic: 0, underlined: 1, struck_out: 0, pitch_and_family: 0x31, charset: 1 });
        assert_eq!(bytes.len(), 60);
        assert_eq!(i32::from_le_bytes(bytes[28..32].try_into().unwrap()), 400);
        assert_eq!(u16::from_le_bytes(bytes[46..48].try_into().unwrap()), 0xffff);
        assert_eq!(&bytes[52..57], &[0, 1, 0, 0x31, 1]);
        assert!(bytes[57..].iter().all(|byte| *byte == 0));
    }
}
