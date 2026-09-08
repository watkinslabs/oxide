//! Font-family query kinds: expected result sizes and per-kind result admission.
//!
//! Field mapping per kind is fixed by this module and the raw ABI decoder that
//! fills it; every destination byte count is derived here so the kernel copy
//! path never trusts a callback-supplied length.
use super::{QueryRequest, QueryOutput, GDI_ERROR, MAX_QUERY_BYTES};

pub const QUERY_ENUM_FONTS: u32 = 8;
pub const QUERY_CHAR_WIDTH: u32 = 9;
pub const QUERY_WIDTH_INFO: u32 = 10;
pub const QUERY_UNICODE_RANGES: u32 = 11;
pub const QUERY_GLYPH_OUTLINE: u32 = 12;
pub const QUERY_KERNING_PAIRS: u32 = 13;
pub const QUERY_TEXT_FACE: u32 = 14;
pub const QUERY_REALIZATION: u32 = 15;
pub const QUERY_FONT_FILE_DATA: u32 = 16;
pub const QUERY_FONT_FILE_INFO: u32 = 17;
pub const QUERY_MAKE_FONT_DIR: u32 = 18;
pub const QUERY_ADD_FONT_RESOURCE: u32 = 19;
pub const QUERY_REMOVE_FONT_RESOURCE: u32 = 20;
pub const QUERY_ADD_MEM_FONT: u32 = 21;
pub const QUERY_REMOVE_MEM_FONT: u32 = 22;
/// Advances of one face, answered into kernel state rather than a caller's
/// buffer: the menu layout measures every label from this table because it
/// cannot re-enter the font backend inside the message that needs the number.
pub const QUERY_MENU_CELLS: u32 = 23;
/// First character that table measures: the printable block begins here.
pub const MENU_CELL_FIRST: u32 = 0x20;
/// Characters it covers, through the last printable ASCII character.
pub const MENU_CELL_COUNT: u32 = 0x5f;
/// Sub-pixel units one stored advance is quoted in, so a run sums before it
/// rounds once.
pub const MENU_CELL_SCALE: i32 = 16;
/// Bytes the answer occupies: the face's cell height, then one word per
/// character.
pub const MENU_CELL_BYTES: u32 = 4 + MENU_CELL_COUNT * 2;

/// Kinds the kernel itself consumes: the answer is retained in kernel state
/// and no caller buffer is written. # C: O(1)
pub fn kernel_sunk(kind: u32) -> bool { kind == QUERY_MENU_CELLS }

/// Windows record sizes consumed by these kinds.
pub const ENUM_ENTRY_BYTES: u32 = 452;
pub const CHAR_WIDTH_INFO_BYTES: u32 = 12;
pub const GLYPHSET_HEADER_BYTES: u32 = 16;
pub const GLYPH_METRICS_BYTES: u32 = 20;
pub const KERNING_PAIR_BYTES: u32 = 8;
pub const REALIZATION_V0_BYTES: u32 = 16;
pub const REALIZATION_BYTES: u32 = 24;
pub const FILE_INFO_BYTES: u32 = 24;
pub const FONT_DIR_BYTES: u32 = 251;
pub const MAT2_WORDS: u32 = 8;
pub const FACE_NAME_WORDS: u32 = 32;

/// Kinds addressed by realization handle or resource path rather than a device context. # C: O(1)
pub fn deviceless(kind: u32) -> bool {
    matches!(kind, QUERY_FONT_FILE_DATA | QUERY_FONT_FILE_INFO | QUERY_MAKE_FONT_DIR
        | QUERY_ADD_FONT_RESOURCE | QUERY_REMOVE_FONT_RESOURCE | QUERY_ADD_MEM_FONT | QUERY_REMOVE_MEM_FONT
        | QUERY_MENU_CELLS)
}

/// Leading result bytes belonging to the secondary destination, not the main buffer.
/// A caller that passes no secondary pointer receives no prefix. # C: O(1)
pub fn aux_prefix(request: &QueryRequest) -> u32 {
    if request.aux == 0 { return 0; }
    match request.kind {
        QUERY_ENUM_FONTS | QUERY_ADD_MEM_FONT => 4,
        QUERY_GLYPH_OUTLINE => GLYPH_METRICS_BYTES,
        QUERY_FONT_FILE_INFO => 8,
        _ => 0,
    }
}

/// API failure value returned when the request never reaches the font backend. # C: O(1)
pub fn failure(kind: u32) -> u64 {
    match kind {
        QUERY_GLYPH_OUTLINE => GDI_ERROR as u64,
        QUERY_ADD_FONT_RESOURCE | QUERY_REMOVE_FONT_RESOURCE | QUERY_REMOVE_MEM_FONT => 1,
        _ => 0,
    }
}

/// Admit the request shape; `Some` carries the maximum main-destination byte count. # C: O(1)
pub fn capacity_limit(request: &QueryRequest) -> Option<u32> {
    let bytes = match request.kind {
        QUERY_ENUM_FONTS => {
            if request.aux == 0 || request.count > FACE_NAME_WORDS { return None; }
            request.capacity / ENUM_ENTRY_BYTES * ENUM_ENTRY_BYTES
        }
        QUERY_CHAR_WIDTH => {
            if request.output == 0 || request.count == 0 { return None; }
            request.count.checked_mul(4)?
        }
        QUERY_WIDTH_INFO => { if request.output == 0 { return None; } CHAR_WIDTH_INFO_BYTES }
        QUERY_UNICODE_RANGES => MAX_QUERY_BYTES,
        QUERY_GLYPH_OUTLINE => {
            if request.count != MAT2_WORDS || request.input == 0 || request.capacity > MAX_QUERY_BYTES { return None; }
            if request.output == 0 { 0 } else { request.capacity }
        }
        QUERY_KERNING_PAIRS => {
            if request.value > u32::MAX as u64 || request.capacity > MAX_QUERY_BYTES { return None; }
            if request.output == 0 || request.value == 0 { 0 } else { request.capacity }
        }
        QUERY_TEXT_FACE => { if request.capacity > MAX_QUERY_BYTES { return None; } request.capacity }
        QUERY_REALIZATION => {
            if request.output == 0 || !matches!(request.capacity, REALIZATION_V0_BYTES | REALIZATION_BYTES) { return None; }
            request.capacity
        }
        QUERY_FONT_FILE_DATA => {
            if request.output == 0 || request.capacity == 0 || request.capacity > MAX_QUERY_BYTES { return None; }
            request.capacity
        }
        QUERY_FONT_FILE_INFO => {
            if request.aux == 0 || request.capacity > MAX_QUERY_BYTES { return None; }
            request.capacity
        }
        QUERY_MAKE_FONT_DIR => {
            if request.output == 0 || request.count == 0 || request.capacity < FONT_DIR_BYTES { return None; }
            FONT_DIR_BYTES
        }
        QUERY_ADD_FONT_RESOURCE | QUERY_REMOVE_FONT_RESOURCE => {
            if request.count == 0 || request.input == 0 || request.output != 0 { return None; }
            0
        }
        QUERY_ADD_MEM_FONT => {
            if request.value == 0 || request.capacity == 0 || request.aux == 0 { return None; }
            request.value.checked_add(request.capacity as u64)?;
            0
        }
        QUERY_REMOVE_MEM_FONT => { if request.output != 0 { return None; } 0 }
        QUERY_MENU_CELLS => {
            if request.output != 0 || request.aux != 0 || request.count != 0 || request.input != 0
                || request.capacity != MENU_CELL_BYTES { return None; }
            MENU_CELL_BYTES
        }
        _ => return None,
    };
    if request.aux.checked_add(aux_prefix(request) as u64).is_none() { return None; }
    request.output.checked_add(bytes as u64)?;
    Some(bytes)
}

/// Validate the complete callback answer before any destination byte is written. # C: O(1)
pub fn accepts(request: &QueryRequest, out: &QueryOutput) -> bool {
    let Some(limit) = capacity_limit(request) else { return false; };
    let prefix = aux_prefix(request);
    // A kind that produced nothing writes nothing, including its secondary record.
    if out.length == 0 { return empty_result(request, out); }
    if out.length < prefix || out.length - prefix > limit { return false; }
    let body = out.length - prefix;
    match request.kind {
        QUERY_ENUM_FONTS => out.result <= 1 && prefix == 4 && body % ENUM_ENTRY_BYTES == 0
            && (request.output != 0 || body == 0),
        QUERY_CHAR_WIDTH => out.result == 1 && body == request.count * 4,
        QUERY_WIDTH_INFO => out.result == 1 && body == CHAR_WIDTH_INFO_BYTES,
        QUERY_UNICODE_RANGES => out.result >= GLYPHSET_HEADER_BYTES && out.result % 4 == 0
            && body == if request.output == 0 { 0 } else { out.result },
        QUERY_GLYPH_OUTLINE => out.result != GDI_ERROR && body <= limit
            && (request.output == 0 || request.capacity == 0 || body == out.result),
        QUERY_KERNING_PAIRS => body % KERNING_PAIR_BYTES == 0
            && (limit == 0 || u64::from(body / KERNING_PAIR_BYTES) == u64::from(out.result).min(request.value)),
        QUERY_TEXT_FACE => body == if request.output == 0 { 0 } else { out.result * 2 },
        QUERY_REALIZATION => out.result == 1 && body == request.capacity,
        QUERY_FONT_FILE_DATA => (out.result == 1 && body == request.capacity) || (out.result == 0 && body == 0),
        QUERY_FONT_FILE_INFO => out.result <= 1 && body == if out.result == 1 { request.capacity } else { 0 },
        QUERY_MAKE_FONT_DIR => (out.result != 0 && body == FONT_DIR_BYTES) || (out.result == 0 && body == 0),
        QUERY_ADD_FONT_RESOURCE | QUERY_REMOVE_FONT_RESOURCE | QUERY_REMOVE_MEM_FONT => body == 0,
        QUERY_ADD_MEM_FONT => body == 0 && out.result != 0,
        QUERY_MENU_CELLS => out.result == 1 && body == MENU_CELL_BYTES,
        _ => false,
    }
}

/// Kinds whose zero-length answer is a complete, admissible API result. # C: O(1)
fn empty_result(request: &QueryRequest, out: &QueryOutput) -> bool {
    match request.kind {
        QUERY_ENUM_FONTS | QUERY_CHAR_WIDTH | QUERY_WIDTH_INFO | QUERY_REALIZATION | QUERY_MENU_CELLS => false,
        QUERY_UNICODE_RANGES => request.output == 0 && out.result >= GLYPHSET_HEADER_BYTES,
        QUERY_GLYPH_OUTLINE => request.aux == 0 && out.result != GDI_ERROR
            && (request.output == 0 || request.capacity == 0 || out.result == 0),
        QUERY_KERNING_PAIRS => capacity_limit(request) == Some(0) || out.result == 0,
        QUERY_TEXT_FACE => request.output == 0 || out.result == 0,
        QUERY_FONT_FILE_DATA => out.result == 0,
        QUERY_FONT_FILE_INFO => out.result == 0,
        QUERY_MAKE_FONT_DIR => out.result == 0,
        QUERY_ADD_FONT_RESOURCE | QUERY_REMOVE_FONT_RESOURCE | QUERY_REMOVE_MEM_FONT => true,
        QUERY_ADD_MEM_FONT => out.result == 0,
        _ => false,
    }
}
