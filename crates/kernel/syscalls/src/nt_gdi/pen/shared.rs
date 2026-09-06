//! Admit one complete client DC snapshot before canonical raster mutation.
use ipc::win32_gdi::PenRasterState;
use syscall::nt_gdi_client::{self as abi,Error};

/// # C: O(1)
pub(super) fn decode(bytes:&[u8],dc:u32)->Result<PenRasterState,Error>{
    let text=abi::decode_text(bytes,dc)?;
    let word=|offset|u16::from_le_bytes([bytes[offset],bytes[offset+1]]);
    let dword=|offset|u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap());
    let rop=word(abi::dc::ROP_MODE);let arc=dword(abi::dc::ARC_DIRECTION);
    if !(1..=16).contains(&rop)||!(1..=2).contains(&arc){return Err(Error::UnsupportedTransform);}
    Ok(PenRasterState{position:text.current_position,rop,clockwise:arc==2,
        pen_color:abi::colorref_to_xrgb(dword(abi::dc::PEN_COLOR))?,
        brush_color:abi::colorref_to_xrgb(dword(abi::dc::BRUSH_COLOR))?,
        background:text.background,opaque:text.background_mode==2})
}

#[cfg(test)]
#[path="tests/shared.rs"]
mod tests;
