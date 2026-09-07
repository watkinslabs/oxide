//! The system-service numbering the guest will actually use, read out of the
//! module the image stages.
//!
//! Service ordinals are fixed when the runtime is built. Transcribing them
//! into this tree would make a version bump able to renumber the services
//! silently, so the numbers are decoded from the shipped stub bodies instead
//! and the table here only says which names are services.

use std::collections::BTreeMap;
use std::path::Path;

use super::catalog;

/// One exported name and the ordinal its stub asks the kernel entry to run.
pub struct DecodedService { pub name: String, pub ordinal: u32, pub flag_address: u64 }

/// Every export whose body is a system-service stub, decoded from the image.
/// `None` when the catalog carries no runtime module to read.
/// # C: O(export names * name bytes)
pub fn decode(root: &Path) -> Option<Vec<DecodedService>> {
    let blob = catalog::read(root, catalog::RUNTIME_MODULE)?;
    let image = pe::parse(&blob).ok()?;
    let exports = image.exports().ok()??;
    let mut decoded = Vec::new();
    for index in 0..exports.name_count {
        let name_rva_bytes = image.rva_range(exports.names_rva + index * 4, 4).ok()?;
        let name_rva = u32::from_le_bytes(name_rva_bytes.try_into().ok()?);
        let name = read_c_string(&image, name_rva)?;
        let ordinal_bytes = image.rva_range(exports.ordinals_rva + index * 2, 2).ok()?;
        let slot = u16::from_le_bytes(ordinal_bytes.try_into().ok()?) as u32;
        if slot >= exports.function_count { continue; }
        let function_bytes = image.rva_range(exports.functions_rva + slot * 4, 4).ok()?;
        let rva = u32::from_le_bytes(function_bytes.try_into().ok()?);
        if rva == 0 { continue; }
        let Ok(body) = image.rva_range(rva, pe::ntdll::stub::SERVICE_STUB_BYTES as u32) else { continue };
        let Some(stub) = pe::ntdll::stub::decode(body) else { continue };
        decoded.push(DecodedService { name, ordinal: stub.ordinal, flag_address: stub.flag_address });
    }
    Some(decoded)
}

/// Decoded services keyed by name. # C: O(services log services)
pub fn by_name(decoded: &[DecodedService]) -> BTreeMap<&str, u32> {
    decoded.iter().map(|service| (service.name.as_str(), service.ordinal)).collect()
}

fn read_c_string(image: &pe::Image<'_>, rva: u32) -> Option<String> {
    let mut length = 0u32;
    loop {
        let byte = image.rva_range(rva + length, 1).ok()?[0];
        if byte == 0 { break; }
        length += 1;
        if length > 512 { return None; }
    }
    let bytes = image.rva_range(rva, length).ok()?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}
