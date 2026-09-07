//! win32u export -> syscall ordinal, decoded from the shipped stub bytes.

/// The x86-64 win32u export body is a fixed service thunk: the request
/// register is copied to r10, the service ordinal is loaded into eax as a
/// 32-bit immediate, and the syscall instruction follows. The immediate is
/// the ordinal the kernel entry admits.
const MOVE_REQUEST_REGISTER: [u8; 3] = [0x4c, 0x8b, 0xd1];
const LOAD_ORDINAL_IMMEDIATE: u8 = 0xb8;
const STUB_PREFIX_BYTES: u32 = 8;

/// # C: O(1)
pub fn stub_ordinal(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < STUB_PREFIX_BYTES as usize { return None; }
    if bytes[..3] != MOVE_REQUEST_REGISTER || bytes[3] != LOAD_ORDINAL_IMMEDIATE { return None; }
    Some(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u64)
}

/// Resolve one exported name to its service ordinal. # C: O(N_export_names)
pub fn ordinal_of(image: &pe::Image<'_>, name: &[u8]) -> Option<u64> {
    let target = image.export_target(&pe::ImportThunk::Name { hint: 0, name }).ok()??;
    let pe::ExportTarget::Rva(rva) = target else { return None };
    stub_ordinal(image.rva_range(rva, STUB_PREFIX_BYTES).ok()?)
}
