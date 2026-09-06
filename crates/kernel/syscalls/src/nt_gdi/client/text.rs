//! Field-level shared DC_ATTR access for bound canonical GDI state.

#![cfg(target_os = "oxide-kernel")]

use super::{ClientBinding, ClientError};
use syscall::nt_gdi_client as abi;

const FOREGROUND: u32 = 0;
const BACKGROUND: u32 = 1;
const BACKGROUND_MODE: u32 = 2;
const ALIGNMENT: u32 = 3;

pub(super) fn snapshot(binding: ClientBinding, handle: u32) -> Result<abi::DcText, ClientError> {
    let bytes = binding.read_dc_attr(handle)?;
    abi::decode_text(&bytes, handle).map_err(|_| ClientError::Codec)
}

pub(super) fn set_attribute(binding: ClientBinding, handle: u32, attribute: u32, value: u32) -> Result<u32, ClientError> {
    let mut bytes = binding.read_dc_attr(handle)?;
    let current = abi::decode_text(&bytes, handle).map_err(|_| ClientError::Codec)?;
    let (offset, width, old, encoded) = match attribute {
        FOREGROUND => (abi::dc::TEXT_COLOR, 4, current.foreground, abi::xrgb_to_colorref(value).map_err(|_| ClientError::Codec)?),
        BACKGROUND => (abi::dc::BACKGROUND_COLOR, 4, current.background, abi::xrgb_to_colorref(value).map_err(|_| ClientError::Codec)?),
        BACKGROUND_MODE if value == 1 || value == 2 => (abi::dc::BACKGROUND_MODE, 2, current.background_mode, value),
        ALIGNMENT => {
            let mut candidate = current; candidate.alignment = value;
            if abi::encode_dc_attr(handle, 1, 1, candidate).is_err() { return Err(ClientError::Codec); }
            (abi::dc::TEXT_ALIGN, 2, current.alignment, value)
        }
        _ => return Err(ClientError::Codec),
    };
    if width == 4 { bytes[offset..offset + 4].copy_from_slice(&encoded.to_le_bytes()); }
    else { bytes[offset..offset + 2].copy_from_slice(&(encoded as u16).to_le_bytes()); }
    // Validate the prospective record, but commit only the field selected by
    // this operation so unrelated client writes survive concurrently.
    abi::decode_text(&bytes, handle).map_err(|_| ClientError::Codec)?;
    let address = binding.dc_attr_address(handle)?.checked_add(offset as u64).ok_or(ClientError::InvalidBinding)?;
    if width == 4 { uaccess::copy_to_user(address, &encoded.to_le_bytes()).map_err(|_| ClientError::UserCopy)?; }
    else { uaccess::copy_to_user(address, &(encoded as u16).to_le_bytes()).map_err(|_| ClientError::UserCopy)?; }
    Ok(old)
}

pub(super) fn set_position(binding: ClientBinding, handle: u32, position: (i32, i32)) -> Result<(i32, i32), ClientError> {
    let bytes = binding.read_dc_attr(handle)?;
    let current = abi::decode_text(&bytes, handle).map_err(|_| ClientError::Codec)?;
    let mut encoded = [0u8; 8];
    encoded[..4].copy_from_slice(&(position.0 as u32).to_le_bytes());
    encoded[4..].copy_from_slice(&(position.1 as u32).to_le_bytes());
    let address = binding.dc_attr_address(handle)?.checked_add(abi::dc::CUR_POS as u64).ok_or(ClientError::InvalidBinding)?;
    uaccess::copy_to_user(address, &encoded).map_err(|_| ClientError::UserCopy)?;
    Ok(current.current_position)
}
