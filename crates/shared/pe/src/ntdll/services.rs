//! The system-service numbering a shipped module actually uses.
//!
//! Service ordinals are fixed when the module is built. Transcribing them into
//! this tree would let a version bump renumber the services silently, so they
//! are decoded from the shipped stub bodies and only the name set says which
//! exports are services at all.

use alloc::vec::Vec;
use crate::{Error, Image};

/// One exported name and the ordinal its stub asks the kernel entry to run.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DecodedService<'a> {
    pub name: &'a [u8],
    pub ordinal: u32,
    /// Absolute address of the flag byte the stub tests before the syscall leg.
    pub flag_address: u64,
}

/// Every export of `image` whose body is a system-service stub, in export-name
/// order. An export whose body is not the shipped stub shape is library code
/// and is skipped rather than guessed at.
/// # C: O(export names * name bytes)
pub fn decode_all<'a>(image: &Image<'a>) -> Result<Vec<DecodedService<'a>>, Error> {
    let Some(exports) = image.exports()? else { return Ok(Vec::new()); };
    let mut out = Vec::new();
    for index in 0..exports.name_count {
        let name_rva = read_u32(image, exports.names_rva, index, 4)?;
        let name = image.c_string(name_rva)?;
        let slot = {
            let at = exports.ordinals_rva.checked_add(index.checked_mul(2).ok_or(Error::Einval)?).ok_or(Error::Einval)?;
            let bytes = image.rva_range(at, 2)?;
            u16::from_le_bytes([bytes[0], bytes[1]]) as u32
        };
        if slot >= exports.function_count { continue; }
        let rva = read_u32(image, exports.functions_rva, slot, 4)?;
        if rva == 0 { continue; }
        let Ok(body) = image.rva_range(rva, super::stub::SERVICE_STUB_BYTES as u32) else { continue };
        let Some(stub) = super::stub::decode(body) else { continue };
        out.push(DecodedService { name, ordinal: stub.ordinal, flag_address: stub.flag_address });
    }
    Ok(out)
}

fn read_u32(image: &Image<'_>, base: u32, index: u32, stride: u32) -> Result<u32, Error> {
    let at = base.checked_add(index.checked_mul(stride).ok_or(Error::Einval)?).ok_or(Error::Einval)?;
    let bytes = image.rva_range(at, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
