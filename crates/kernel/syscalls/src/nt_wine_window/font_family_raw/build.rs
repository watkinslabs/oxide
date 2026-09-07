//! Per-ordinal field placement for the font-family query record.
use super::*;

fn dword(value: u64) -> u32 { value as u32 }
fn bounded(bytes: u64) -> Option<u32> { (bytes <= abi::MAX_QUERY_BYTES as u64).then_some(bytes as u32) }

pub(super) fn build(ordinal: u64, args: &[u64], fetched: Option<u64>) -> Option<Request> {
    match ordinal {
        FONT_IS_LINKED => return Some(Request::FontIsLinked),
        GET_RASTERIZER_CAPS => return Some(Request::RasterizerCaps { status: args[0] }),
        SET_TEXT_JUSTIFICATION => return Some(Request::Justify { dc: args[0], extra: args[1] as i32, breaks: args[2] as i32 }),
        _ => {}
    }
    let mut request = blank(args[0], super::query_kind(ordinal)?);
    match ordinal {
        ENUM_FONTS => {
            request.flags = dword(args[1]);
            request.count = dword(args[3]);
            request.input = if request.count == 0 { 0 } else { args[4] };
            request.first = dword(args[5]);
            request.aux = args[6];
            request.capacity = bounded(fetched? & 0xffff_ffff)?;
            request.output = args[7];
        }
        GET_CHAR_WIDTH_W => {
            request.first = dword(args[1]);
            request.input = args[3];
            request.flags = dword(args[4]);
            request.output = args[5];
            let last = dword(args[2]);
            request.count = if request.flags & CHAR_WIDTH_INDICES != 0 || request.input != 0 { last }
                else { last.wrapping_sub(request.first).wrapping_add(1) };
        }
        GET_CHAR_WIDTH_INFO => { request.output = args[1]; request.capacity = abi::CHAR_WIDTH_INFO_BYTES; }
        GET_FONT_UNICODE_RANGES => request.output = args[1],
        GET_GLYPH_OUTLINE => {
            // The reference refuses the call outright when no transform is supplied.
            if args[6] == 0 { return None; }
            request.first = dword(args[1]) & 0xffff;
            request.flags = dword(args[2]);
            request.aux = args[3];
            request.capacity = bounded(args[4])?;
            request.output = args[5];
            request.input = args[6];
            request.count = abi::MAT2_WORDS;
        }
        GET_KERNING_PAIRS => {
            // A zero pair count with a destination is the caller's error, not a size query.
            if args[1] == 0 && args[2] != 0 { return None; }
            request.value = dword(args[1]) as u64;
            request.output = args[2];
            request.capacity = if request.output == 0 { 0 } else { bounded(request.value * abi::KERNING_PAIR_BYTES as u64)? };
        }
        GET_TEXT_FACE_W => {
            request.value = args[1] as i32 as i64 as u64;
            request.output = args[2];
            let count = args[1] as i32;
            request.capacity = if request.output == 0 || count <= 0 { 0 } else { bounded(count as u64 * 2)? };
        }
        GET_REALIZATION_INFO => { request.output = args[1]; request.capacity = dword(fetched?); }
        GET_FONT_FILE_DATA => {
            request.dc = 0;
            request.first = dword(args[0]);
            request.offset = dword(args[1]);
            request.value = fetched?;
            request.output = args[3];
            request.capacity = bounded(args[4])?;
        }
        GET_FONT_FILE_INFO => {
            request.dc = 0;
            request.first = dword(args[0]);
            request.offset = dword(args[1]);
            request.output = args[2];
            request.capacity = bounded(args[3])?;
            request.aux = args[4];
        }
        MAKE_FONT_DIR => {
            request.dc = 0;
            request.flags = dword(args[0]);
            request.output = args[1];
            request.capacity = bounded(args[2])?;
            request.input = args[3];
            let bytes = dword(args[4]);
            if bytes <= 2 || bytes % 2 != 0 { return None; }
            request.count = bytes / 2;
        }
        ADD_FONT_RESOURCE_W | REMOVE_FONT_RESOURCE_W => {
            request.dc = 0;
            request.input = args[0];
            request.count = dword(args[1]);
            request.flags = dword(args[3]);
        }
        ADD_FONT_MEM_RESOURCE_EX => {
            request.dc = 0;
            request.value = args[0];
            request.capacity = dword(args[1]);
            request.aux = args[4];
        }
        REMOVE_FONT_MEM_RESOURCE_EX => { request.dc = 0; request.value = args[0]; }
        _ => return None,
    }
    request.aux_bytes = abi::aux_prefix(&request);
    Some(Request::Query(request))
}
