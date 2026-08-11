use super::*;

const RMRR_LEN: usize = 24;
const PAGE_BYTES: u64 = 4096;
pub const MAX_RMRR_SCOPES: usize = 16;

/// Firmware-reserved DMA range plus its exact device scopes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DmarRmrr {
    pub segment: u16,
    pub base: u64,
    pub end: u64,
    pub scopes: [DmarScope; MAX_RMRR_SCOPES],
    pub scope_count: usize,
}

pub(super) fn parse(t: &[u8], off: usize, end: usize, inv: &mut IommuInventory) -> Result<(), IommuError> {
    if end - off < RMRR_LEN || inv.dmar_rmrr_count == MAX_DMAR_RMRRS { return Err(IommuError::BadRecord); }
    let base = le64(t, off + 8);
    let limit = le64(t, off + 16);
    if base & (PAGE_BYTES - 1) != 0 || limit < base || limit.checked_add(1).is_none_or(|next| next & (PAGE_BYTES - 1) != 0) { return Err(IommuError::BadRecord); }
    let mut scopes = [DmarScope { unit_index: DMAR_RMRR_SCOPE_UNIT, scope_type: 0, enumeration_id: 0, start_bus: 0, path_len: 0, path: [0; MAX_DMAR_PATH_BYTES] }; MAX_RMRR_SCOPES];
    let scope_count = parse_rmrr_scopes(t, off + RMRR_LEN, end, &mut scopes)?;
    inv.dmar_rmrrs[inv.dmar_rmrr_count] = DmarRmrr { segment: le16(t, off + 6), base, end: limit, scopes, scope_count };
    inv.dmar_rmrr_count += 1;
    Ok(())
}

fn parse_rmrr_scopes(t: &[u8], mut off: usize, end: usize, scopes: &mut [DmarScope; MAX_RMRR_SCOPES]) -> Result<usize, IommuError> {
    let mut count = 0;
    while off < end {
        if end - off < DMAR_SCOPE_LEN { return Err(IommuError::BadRecord); }
        let len = t[off + 1] as usize;
        if len < DMAR_SCOPE_LEN || len > end - off || (len - DMAR_SCOPE_LEN) % 2 != 0 { return Err(IommuError::BadRecord); }
        if count == MAX_RMRR_SCOPES { return Err(IommuError::TooManyScopes); }
        let path_len = len - DMAR_SCOPE_LEN;
        if path_len > MAX_DMAR_PATH_BYTES { return Err(IommuError::ScopePathTooLong); }
        let mut path = [0; MAX_DMAR_PATH_BYTES];
        path[..path_len].copy_from_slice(&t[off + DMAR_SCOPE_LEN..off + len]);
        scopes[count] = DmarScope { unit_index: DMAR_RMRR_SCOPE_UNIT, scope_type: t[off], enumeration_id: t[off + 4], start_bus: t[off + 5], path_len: path_len as u8, path };
        count += 1;
        off += len;
    }
    if off == end { Ok(count) } else { Err(IommuError::BadRecord) }
}
