//! Native selected-font query decoding and canonical snapshot/callback boundary; 31ge§5.
use ipc::win32_gdi::Font;
use syscall::nt_native_gdi as abi;

pub(crate) const GET_CHAR_ABC_WIDTHS: u64 = 0x11e6;
pub(crate) const GET_FONT_DATA: u64 = 0x11fe;
pub(crate) const GET_GLYPH_INDICES: u64 = 0x1204;
pub(crate) const GET_OUTLINE_METRICS: u64 = 0x1211;
pub(crate) const GET_TEXT_CHARSET: u64 = 0x1225;

fn signature(ordinal: u64) -> Option<(u32, usize)> {
    Some(match ordinal {
        GET_TEXT_CHARSET => (abi::QUERY_CHARSET, 3),
        GET_FONT_DATA => (abi::QUERY_DATA, 5),
        GET_GLYPH_INDICES => (abi::QUERY_GLYPHS, 5),
        GET_CHAR_ABC_WIDTHS => (abi::QUERY_ABC, 6),
        GET_OUTLINE_METRICS => (abi::QUERY_OUTLINE, 4),
        _ => return None,
    })
}

/// Admit exactly the raw signature before entry-layer stack collection. # C: O(1)
pub(crate) fn argument_count(ordinal: u64) -> Option<usize> { signature(ordinal).map(|(_, count)| count) }

/// Recognized malformed calls stay claimed in their API failure domain. # C: O(1)
pub(crate) fn decode(ordinal: u64, args: &[u64]) -> Option<Result<abi::QueryRequest, u64>> {
    let (kind, count) = signature(ordinal)?;
    let mut request = abi::QueryRequest { version: abi::VERSION, size: core::mem::size_of::<abi::QueryRequest>() as u32,
        dc: 0, kind, flags: 0, height: 0, width: 0, weight: 0, italic: 0,
        first: 0, count: 0, input: 0, output: 0, table: 0, offset: 0, capacity: 0, reserved: 0 };
    let failure = request.failure();
    if args.len() < count { return Some(Err(failure)); }
    request.dc = args[0];
    match kind {
        abi::QUERY_CHARSET => { request.output = args[1]; request.flags = args[2] as u32; }
        abi::QUERY_DATA => {
            request.table = args[1] as u32; request.offset = args[2] as u32;
            request.output = args[3]; request.capacity = if request.output == 0 { 0 } else { args[4] as u32 };
        }
        abi::QUERY_GLYPHS => {
            request.input = args[1]; request.count = args[2] as u32;
            request.output = args[3]; request.flags = args[4] as u32;
        }
        abi::QUERY_ABC => {
            request.first = args[1] as u32; request.input = args[3];
            request.flags = args[4] as u32; request.output = args[5];
            if request.output == 0 { return Some(Err(failure)); }
            let last = args[2] as u32;
            request.count = if request.flags & abi::ABC_INDICES != 0 || request.input != 0 { last }
                else { last.wrapping_sub(request.first).wrapping_add(1) };
        }
        abi::QUERY_OUTLINE => {
            request.output = args[2]; request.capacity = if request.output == 0 { 0 } else { args[1] as u32 };
            request.flags = args[3] as u32;
        }
        _ => return Some(Err(failure)),
    }
    Some(if request.valid() { Ok(request) } else { Err(failure) })
}

/// Consume an owned canonical font snapshot, never hold a GDI lock through native entry.
/// # C: O(1) plus canonical snapshot and callback entry
pub(crate) fn route(ordinal: u64, args: &[u64], snapshot: impl FnOnce(u64) -> Option<Font>,
    enter: impl FnOnce(abi::QueryRequest) -> u64) -> Option<u64> {
    let mut request = match decode(ordinal, args)? { Ok(request) => request, Err(result) => return Some(result) };
    let failure = request.failure();
    let Some(font) = snapshot(request.dc) else { return Some(failure); };
    request.height = font.height; request.width = font.width; request.weight = font.weight; request.italic = u32::from(font.italic);
    if !request.valid() { return Some(failure); }
    Some(enter(request))
}

#[cfg(test)]
#[path = "tests/font_query_raw.rs"]
mod tests;
