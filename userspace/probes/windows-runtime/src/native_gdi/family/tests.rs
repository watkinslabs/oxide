//! Module manifest: shared realization helper plus one child per family answer.
use syscall::nt_native_gdi as abi;
use super::super::native;

#[path = "tests/enumerate.rs"]
mod enumerate;
#[path = "tests/widths.rs"]
mod widths;
#[path = "tests/glyph.rs"]
mod glyph;
#[path = "tests/resource.rs"]
mod resource;

/// Serialize the tests that add and remove registry faces.
pub(super) static REGISTRY: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(super) fn request(kind: u32) -> abi::QueryRequest {
    abi::QueryRequest { version: abi::VERSION, size: std::mem::size_of::<abi::QueryRequest>() as u32,
        dc: 1, kind, flags: 0, height: 16, width: 0, weight: 400, italic: 0, first: 0, count: 0,
        input: 0, output: 0x10000, table: 0, offset: 0, capacity: 0, reserved: 0,
        aux: 0, value: 0, aux_bytes: 0, reserved2: 0 }
}

pub(super) fn run(request: &abi::QueryRequest, input: &[u16]) -> Option<(u32, Vec<u8>)> {
    native::prepare_fonts().unwrap();
    let mut request = *request;
    request.aux_bytes = abi::aux_prefix(&request);
    assert!(request.valid(), "the kernel would refuse this shape before the backend sees it");
    let font = native::selected_font_with_width(request.height, request.width, request.weight, request.italic)?;
    super::execute(&font, native::selected_bytes(request.weight, request.italic)?, &request, input)
}

pub(super) fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
pub(super) fn short(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
pub(super) fn utf16(text: &str) -> Vec<u16> { text.encode_utf16().chain(std::iter::once(0)).collect() }

#[test]
fn rounded_proportion_matches_the_reference_form() {
    assert_eq!(super::muldiv(32, 2048, 2048), 32);
    assert_eq!(super::muldiv(1, 3, 2), 2);
    assert_eq!(super::muldiv(-1, 3, 2), -2);
    assert_eq!(super::muldiv(1, 1, 0), -1);
}
