//! Raw win32u font-family ABI: resources, enumeration, glyph and realization
//! queries, and the two calls whose whole answer is decided here.
//!
//! Every ordinal parses into either one native font query or one immediate
//! device-context operation; no work logic and no font data live in this file.
use syscall::nt_native_gdi as abi;

pub(crate) const ADD_FONT_MEM_RESOURCE_EX: u64 = 0x1087;
pub(crate) const ADD_FONT_RESOURCE_W: u64 = 0x1088;
pub(crate) const ENUM_FONTS: u64 = 0x11be;
pub(crate) const FONT_IS_LINKED: u64 = 0x11d6;
pub(crate) const GET_CHAR_WIDTH_INFO: u64 = 0x11e8;
pub(crate) const GET_CHAR_WIDTH_W: u64 = 0x11e9;
pub(crate) const GET_FONT_FILE_DATA: u64 = 0x11ff;
pub(crate) const GET_FONT_FILE_INFO: u64 = 0x1200;
pub(crate) const GET_FONT_UNICODE_RANGES: u64 = 0x1202;
pub(crate) const GET_GLYPH_OUTLINE: u64 = 0x1206;
pub(crate) const GET_KERNING_PAIRS: u64 = 0x1207;
pub(crate) const GET_RASTERIZER_CAPS: u64 = 0x121b;
pub(crate) const GET_REALIZATION_INFO: u64 = 0x121c;
pub(crate) const GET_TEXT_FACE_W: u64 = 0x1228;
pub(crate) const MAKE_FONT_DIR: u64 = 0x123b;
pub(crate) const REMOVE_FONT_MEM_RESOURCE_EX: u64 = 0x125a;
pub(crate) const REMOVE_FONT_RESOURCE_W: u64 = 0x125b;
pub(crate) const SET_TEXT_JUSTIFICATION: u64 = 0x128a;

/// Widths are requested by glyph index rather than character code.
pub(crate) const CHAR_WIDTH_INDICES: u32 = 0x08;
/// TrueType rasterization is present and enabled for this realization.
pub(crate) const RASTERIZER_AVAILABLE: u16 = 0x0001;
pub(crate) const RASTERIZER_ENABLED: u16 = 0x0002;
pub(crate) const RASTERIZER_STATUS_BYTES: usize = 6;

const SIGNATURES: &[(u64, usize)] = &[
    (ADD_FONT_MEM_RESOURCE_EX, 5), (ADD_FONT_RESOURCE_W, 6), (ENUM_FONTS, 8), (FONT_IS_LINKED, 1),
    (GET_CHAR_WIDTH_INFO, 2), (GET_CHAR_WIDTH_W, 6), (GET_FONT_FILE_DATA, 5), (GET_FONT_FILE_INFO, 5),
    (GET_FONT_UNICODE_RANGES, 2), (GET_GLYPH_OUTLINE, 8), (GET_KERNING_PAIRS, 3), (GET_RASTERIZER_CAPS, 2),
    (GET_REALIZATION_INFO, 2), (GET_TEXT_FACE_W, 4), (MAKE_FONT_DIR, 5), (REMOVE_FONT_MEM_RESOURCE_EX, 1),
    (REMOVE_FONT_RESOURCE_W, 6), (SET_TEXT_JUSTIFICATION, 3),
];

/// Admit exactly the raw signature before any stack collection. # C: O(number of ordinals)
pub(crate) fn argument_count(ordinal: u64) -> Option<usize> {
    SIGNATURES.iter().find(|entry| entry.0 == ordinal).map(|entry| entry.1)
}

/// One decoded call: a native font query, or an answer this layer already owns.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Request {
    Query(abi::QueryRequest),
    /// No child font is linked into a realization of the installed font set.
    FontIsLinked,
    RasterizerCaps { status: u64 },
    Justify { dc: u64, extra: i32, breaks: i32 },
}

/// Reads the caller must satisfy before the request shape is known.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Prefetch { None, Dword(u64), Qword(u64) }

fn blank(dc: u64, kind: u32) -> abi::QueryRequest {
    abi::QueryRequest { version: abi::VERSION, size: core::mem::size_of::<abi::QueryRequest>() as u32,
        dc, kind, flags: 0, height: 0, width: 0, weight: 0, italic: 0, first: 0, count: 0,
        input: 0, output: 0, table: 0, offset: 0, capacity: 0, reserved: 0,
        aux: 0, value: 0, aux_bytes: 0, reserved2: 0 }
}

/// Which caller word must be read before the request is complete. # C: O(number of ordinals)
pub(crate) fn prefetch(ordinal: u64, args: &[u64]) -> Prefetch {
    match ordinal {
        ENUM_FONTS if args.len() >= 7 => Prefetch::Dword(args[6]),
        GET_REALIZATION_INFO if args.len() >= 2 => Prefetch::Dword(args[1]),
        GET_FONT_FILE_DATA if args.len() >= 3 => Prefetch::Qword(args[2]),
        _ => Prefetch::None,
    }
}

/// Decode one admitted ordinal. `fetched` carries the word named by `prefetch`.
/// # C: O(1)
pub(crate) fn decode(ordinal: u64, args: &[u64], fetched: Option<u64>) -> Option<Result<Request, u64>> {
    let count = argument_count(ordinal)?;
    let kind = query_kind(ordinal);
    let failure = kind.map(abi::failure).unwrap_or(0);
    if args.len() < count { return Some(Err(failure)); }
    Some(build(ordinal, args, fetched).ok_or(failure))
}

fn query_kind(ordinal: u64) -> Option<u32> {
    Some(match ordinal {
        ENUM_FONTS => abi::QUERY_ENUM_FONTS,
        GET_CHAR_WIDTH_W => abi::QUERY_CHAR_WIDTH,
        GET_CHAR_WIDTH_INFO => abi::QUERY_WIDTH_INFO,
        GET_FONT_UNICODE_RANGES => abi::QUERY_UNICODE_RANGES,
        GET_GLYPH_OUTLINE => abi::QUERY_GLYPH_OUTLINE,
        GET_KERNING_PAIRS => abi::QUERY_KERNING_PAIRS,
        GET_TEXT_FACE_W => abi::QUERY_TEXT_FACE,
        GET_REALIZATION_INFO => abi::QUERY_REALIZATION,
        GET_FONT_FILE_DATA => abi::QUERY_FONT_FILE_DATA,
        GET_FONT_FILE_INFO => abi::QUERY_FONT_FILE_INFO,
        MAKE_FONT_DIR => abi::QUERY_MAKE_FONT_DIR,
        ADD_FONT_RESOURCE_W => abi::QUERY_ADD_FONT_RESOURCE,
        REMOVE_FONT_RESOURCE_W => abi::QUERY_REMOVE_FONT_RESOURCE,
        ADD_FONT_MEM_RESOURCE_EX => abi::QUERY_ADD_MEM_FONT,
        REMOVE_FONT_MEM_RESOURCE_EX => abi::QUERY_REMOVE_MEM_FONT,
        _ => return None,
    })
}

/// RASTERIZER_STATUS for this realization: the size field, the availability
/// flags, and a language identifier that is always zero. # C: O(1)
pub(crate) fn rasterizer_status(scalable_backend: bool) -> [u8; RASTERIZER_STATUS_BYTES] {
    let flags = if scalable_backend { RASTERIZER_AVAILABLE | RASTERIZER_ENABLED } else { 0 };
    let mut bytes = [0u8; RASTERIZER_STATUS_BYTES];
    bytes[..2].copy_from_slice(&(RASTERIZER_STATUS_BYTES as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&flags.to_le_bytes());
    bytes
}

/// Split the requested extra device units across break characters. The extra
/// amount is first mapped through the device context extents and taken as a
/// magnitude; a zero amount cancels the break count entirely. # C: O(1)
pub(crate) fn justification(extra: i32, breaks: i32, vport_cx: i32, wnd_cx: i32) -> Option<(i32, i32)> {
    if wnd_cx == 0 { return None; }
    let scaled = (i64::from(extra) * i64::from(vport_cx) + i64::from(wnd_cx) / 2) / i64::from(wnd_cx);
    let extra = i32::try_from(scaled.checked_abs()?).ok()?;
    let breaks = if extra == 0 { 0 } else { breaks };
    if breaks == 0 { return Some((0, 0)); }
    let per = extra / breaks;
    Some((per, extra - breaks * per))
}

/// Resolve one admitted ordinal against the caller, the canonical device
/// context and the native font backend. No GDI lock crosses `enter`.
/// # C: O(1) plus one prefetch word, one canonical snapshot and the callback
pub(crate) fn route(ordinal: u64, args: &[u64],
    read: impl FnOnce(Prefetch) -> Option<u64>,
    snapshot: impl FnOnce(u64) -> Option<ipc::win32_gdi::Font>,
    enter: impl FnOnce(abi::QueryRequest) -> u64,
    immediate: impl FnOnce(Request) -> u64) -> Option<u64> {
    let count = argument_count(ordinal)?;
    let failure = query_kind(ordinal).map(abi::failure).unwrap_or(0);
    if args.len() < count { return Some(failure); }
    let fetched = match prefetch(ordinal, args) {
        Prefetch::None => None,
        needed => match read(needed) { Some(value) => Some(value), None => return Some(failure) },
    };
    let mut request = match decode(ordinal, args, fetched)? {
        Ok(Request::Query(request)) => request,
        Ok(other) => return Some(immediate(other)),
        Err(result) => return Some(result),
    };
    if request.dc != 0 {
        let Some(font) = snapshot(request.dc) else { return Some(failure); };
        request.height = font.height; request.width = font.width;
        request.weight = font.weight; request.italic = u32::from(font.italic);
    }
    if !request.valid() { return Some(failure); }
    Some(enter(request))
}

#[path = "font_family_raw/build.rs"]
mod build_impl;
use build_impl::build;

#[cfg(target_os = "oxide-kernel")]
#[path = "font_family_raw/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/font_family_raw.rs"]
mod tests;
