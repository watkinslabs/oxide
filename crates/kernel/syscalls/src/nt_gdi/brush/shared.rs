//! Shared brush field codec; emits only the owned four bytes, never a DC mirror.
use syscall::nt_gdi_client as abi;

pub(super) fn snapshot(bytes: &[u8; abi::DC_ATTR_SIZE]) -> Result<(u32, u32), abi::Error> {
    let offset = abi::dc::BRUSH_COLOR;
    let raw = u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]);
    Ok((raw, abi::colorref_to_xrgb(raw)?))
}

/// A pattern brush reads text and background beside the brush color; each is
/// the client's own COLORREF field, converted here and never mirrored.
pub(super) fn colors(bytes: &[u8; abi::DC_ATTR_SIZE]) -> Result<ipc::win32_gdi::SharedDcColors, abi::Error> {
    Ok(ipc::win32_gdi::SharedDcColors { brush: snapshot(bytes)?.1,
        text: field(bytes, abi::dc::TEXT_COLOR)?, background: field(bytes, abi::dc::BACKGROUND_COLOR)? })
}

fn field(bytes: &[u8; abi::DC_ATTR_SIZE], offset: usize) -> Result<u32, abi::Error> {
    abi::colorref_to_xrgb(u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]))
}

pub(super) fn replacement(bytes: &[u8; abi::DC_ATTR_SIZE], color: u32) -> Result<(u32, [u8; 4]), abi::Error> {
    let (old, _) = snapshot(bytes)?;
    abi::colorref_to_xrgb(color)?;
    Ok((old, color.to_le_bytes()))
}

#[cfg(test)]
#[path = "tests/shared.rs"]
mod tests;
