// DMAR/IVRS admission and immutable firmware inventory. This is the one
// source of x86 IOMMU-unit ownership; PCI and DMA consumers must read it,
// never rediscover tables or manufacture a second device-to-unit registry.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::acpi::log::{alog_dec, alog_hex, alog_raw};
use crate::acpi::read::read_u32_le;

const ACPI_HEADER_LEN: usize = 36;
const IOMMU_TABLE_HEADER_LEN: usize = 48;
const IVHD_HEADER_LEN: usize = 6;
const IVHD_TYPE_10_LEN: usize = 24;
const IVHD_EXTENDED_LEN: usize = 40;
const DMAR_HEADER_LEN: usize = 4;
const DRHD_LEN: usize = 16;
const DMAR_SCOPE_LEN: usize = 6;
const MAX_TABLE_LEN: usize = 64 * 1024;
pub const MAX_IOMMU_UNITS: usize = 32;
pub const MAX_AMD_IVHD_SCOPES: usize = 256;
const IVHD_TYPE_10: u8 = 0x10;
const IVHD_TYPE_11: u8 = 0x11;
const IVHD_TYPE_40: u8 = 0x40;
const IVHD_DEV_ALL: u8 = 0x01;
const IVHD_DEV_SELECT: u8 = 0x02;
const IVHD_DEV_SELECT_RANGE_START: u8 = 0x03;
const IVHD_DEV_RANGE_END: u8 = 0x04;
const IVHD_DEV_ALIAS: u8 = 0x42;
const IVHD_DEV_ALIAS_RANGE: u8 = 0x43;
const IVHD_DEV_EXT_SELECT: u8 = 0x46;
const IVHD_DEV_EXT_SELECT_RANGE: u8 = 0x47;
const DMAR_TYPE_DRHD: u16 = 0;
const DMAR_INCLUDE_ALL: u8 = 1;
const DMAR_MIN_HOST_ADDRESS_WIDTH: u8 = 11;
const IOMMU_KIND_NONE: u32 = 0;
const IOMMU_KIND_AMD_VI: u32 = 1;
const IOMMU_KIND_INTEL_VTD: u32 = 2;

/// DMA-remapping architecture named by firmware.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IommuKind { AmdVi, IntelVtd }

/// One hardware translation unit and its PCI segment.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IommuUnit {
    pub kind: IommuKind,
    pub segment: u16,
    pub register_base: u64,
    pub include_all: bool,
}

/// One AMD IVHD requester-id interval owned by a translation unit.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AmdIvhdScope {
    pub unit_index: u8,
    pub first_requester: u16,
    pub last_requester: u16,
}

/// Why a firmware IOMMU table was rejected.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IommuError {
    BadSignature,
    BadLength,
    BadChecksum,
    BadRecord,
    TooManyUnits,
    TooManyScopes,
}

/// Parsed architecture and its translation units.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IommuInventory {
    pub kind: IommuKind,
    pub units: [IommuUnit; MAX_IOMMU_UNITS],
    pub unit_count: usize,
    pub amd_scopes: [AmdIvhdScope; MAX_AMD_IVHD_SCOPES],
    pub amd_scope_count: usize,
}

static IOMMU_KIND: AtomicU32 = AtomicU32::new(IOMMU_KIND_NONE);
static IOMMU_COUNT: AtomicU32 = AtomicU32::new(0);
static IOMMU_BASE: [AtomicU64; MAX_IOMMU_UNITS] = [const { AtomicU64::new(0) }; MAX_IOMMU_UNITS];
static IOMMU_SEGMENT: [AtomicU32; MAX_IOMMU_UNITS] = [const { AtomicU32::new(0) }; MAX_IOMMU_UNITS];
static IOMMU_FLAGS: [AtomicU32; MAX_IOMMU_UNITS] = [const { AtomicU32::new(0) }; MAX_IOMMU_UNITS];
static AMD_SCOPE_UNIT: [AtomicU32; MAX_AMD_IVHD_SCOPES] = [const { AtomicU32::new(0) }; MAX_AMD_IVHD_SCOPES];
static AMD_SCOPE_RANGE: [AtomicU32; MAX_AMD_IVHD_SCOPES] = [const { AtomicU32::new(0) }; MAX_AMD_IVHD_SCOPES];
static AMD_SCOPE_COUNT: AtomicU32 = AtomicU32::new(0);

fn le16(t: &[u8], off: usize) -> u16 {
    (t[off] as u16) | ((t[off + 1] as u16) << 8)
}

fn le64(t: &[u8], off: usize) -> u64 {
    let mut v = 0u64;
    let mut i = 0usize;
    while i < 8 { v |= (t[off + i] as u64) << (i * 8); i += 1; }
    v
}

fn checked_table<'a>(t: &'a [u8], sig: &[u8; 4]) -> Result<&'a [u8], IommuError> {
    if t.len() < IOMMU_TABLE_HEADER_LEN { return Err(IommuError::BadLength); }
    if &t[..4] != sig { return Err(IommuError::BadSignature); }
    let len = (t[4] as usize) | ((t[5] as usize) << 8) | ((t[6] as usize) << 16) | ((t[7] as usize) << 24);
    if len < IOMMU_TABLE_HEADER_LEN || len > MAX_TABLE_LEN || len > t.len() { return Err(IommuError::BadLength); }
    let mut sum = 0u8;
    for b in &t[..len] { sum = sum.wrapping_add(*b); }
    if sum != 0 { return Err(IommuError::BadChecksum); }
    Ok(&t[..len])
}

fn push(inv: &mut IommuInventory, unit: IommuUnit) -> Result<(), IommuError> {
    if inv.unit_count == MAX_IOMMU_UNITS { return Err(IommuError::TooManyUnits); }
    inv.units[inv.unit_count] = unit;
    inv.unit_count += 1;
    Ok(())
}

fn push_amd_scope(inv: &mut IommuInventory, unit_index: usize, first_requester: u16, last_requester: u16) -> Result<(), IommuError> {
    if first_requester > last_requester || inv.amd_scope_count == MAX_AMD_IVHD_SCOPES { return Err(IommuError::TooManyScopes); }
    inv.amd_scopes[inv.amd_scope_count] = AmdIvhdScope { unit_index: unit_index as u8, first_requester, last_requester };
    inv.amd_scope_count += 1;
    Ok(())
}

fn parse_ivhd_entries(t: &[u8], start: usize, end: usize, unit_index: usize, inv: &mut IommuInventory) -> Result<(), IommuError> {
    let mut off = start;
    let mut range_start = None;
    while off < end {
        let ty = t[off];
        let len = if ty < 0x80 {
            4usize << (ty >> 6)
        } else if ty == 0xf0 {
            if end - off < 22 { return Err(IommuError::BadRecord); }
            22usize + t[off + 21] as usize
        } else {
            return Err(IommuError::BadRecord);
        };
        if len == 0 || len > end - off { return Err(IommuError::BadRecord); }
        let requester = if len >= 4 { le16(t, off + 2) } else { 0 };
        match ty {
            IVHD_DEV_ALL => push_amd_scope(inv, unit_index, 0, u16::MAX)?,
            IVHD_DEV_SELECT | IVHD_DEV_ALIAS | IVHD_DEV_EXT_SELECT => push_amd_scope(inv, unit_index, requester, requester)?,
            IVHD_DEV_SELECT_RANGE_START | IVHD_DEV_ALIAS_RANGE | IVHD_DEV_EXT_SELECT_RANGE => {
                if range_start.replace(requester).is_some() { return Err(IommuError::BadRecord); }
            }
            IVHD_DEV_RANGE_END => {
                let first = range_start.take().ok_or(IommuError::BadRecord)?;
                push_amd_scope(inv, unit_index, first, requester)?;
            }
            _ => {}
        }
        off += len;
    }
    if off == end && range_start.is_none() { Ok(()) } else { Err(IommuError::BadRecord) }
}

/// Parse a complete AMD IVRS table without touching hardware.
/// # C: O(table bytes)
pub fn parse_ivrs(t: &[u8]) -> Result<IommuInventory, IommuError> {
    let t = checked_table(t, b"IVRS")?;
    let empty = IommuUnit { kind: IommuKind::AmdVi, segment: 0, register_base: 0, include_all: false };
    let empty_scope = AmdIvhdScope { unit_index: 0, first_requester: 0, last_requester: 0 };
    let mut inv = IommuInventory { kind: IommuKind::AmdVi, units: [empty; MAX_IOMMU_UNITS], unit_count: 0,
        amd_scopes: [empty_scope; MAX_AMD_IVHD_SCOPES], amd_scope_count: 0 };
    let mut off = IOMMU_TABLE_HEADER_LEN;
    while off < t.len() {
        if t.len() - off < IVHD_HEADER_LEN { return Err(IommuError::BadRecord); }
        let ty = t[off];
        let len = le16(t, off + 2) as usize;
        if len < IVHD_HEADER_LEN || len > t.len() - off { return Err(IommuError::BadRecord); }
        let end = off + len;
        let hlen = match ty {
            IVHD_TYPE_10 => IVHD_TYPE_10_LEN,
            IVHD_TYPE_11 | IVHD_TYPE_40 => IVHD_EXTENDED_LEN,
            _ => 0,
        };
        if hlen != 0 {
            if len < hlen { return Err(IommuError::BadRecord); }
            parse_ivhd_entries(t, off + hlen, end, inv.unit_count, &mut inv)?;
            push(&mut inv, IommuUnit { kind: IommuKind::AmdVi, segment: le16(t, off + 16), register_base: le64(t, off + 8), include_all: false })?;
        }
        off = end;
    }
    if off != t.len() { return Err(IommuError::BadRecord); }
    Ok(inv)
}

fn validate_drhd_scopes(t: &[u8], start: usize, end: usize) -> Result<(), IommuError> {
    let mut off = start;
    while off < end {
        if end - off < DMAR_SCOPE_LEN { return Err(IommuError::BadRecord); }
        let len = t[off + 1] as usize;
        if len < DMAR_SCOPE_LEN || len > end - off || (len - DMAR_SCOPE_LEN) % 2 != 0 { return Err(IommuError::BadRecord); }
        off += len;
    }
    if off == end { Ok(()) } else { Err(IommuError::BadRecord) }
}

/// Parse a complete Intel DMAR table without touching hardware.
/// # C: O(table bytes)
pub fn parse_dmar(t: &[u8]) -> Result<IommuInventory, IommuError> {
    let t = checked_table(t, b"DMAR")?;
    if t[ACPI_HEADER_LEN] < DMAR_MIN_HOST_ADDRESS_WIDTH { return Err(IommuError::BadRecord); }
    let empty = IommuUnit { kind: IommuKind::IntelVtd, segment: 0, register_base: 0, include_all: false };
    let empty_scope = AmdIvhdScope { unit_index: 0, first_requester: 0, last_requester: 0 };
    let mut inv = IommuInventory { kind: IommuKind::IntelVtd, units: [empty; MAX_IOMMU_UNITS], unit_count: 0,
        amd_scopes: [empty_scope; MAX_AMD_IVHD_SCOPES], amd_scope_count: 0 };
    let mut off = IOMMU_TABLE_HEADER_LEN;
    while off < t.len() {
        if t.len() - off < DMAR_HEADER_LEN { return Err(IommuError::BadRecord); }
        let ty = le16(t, off);
        let len = le16(t, off + 2) as usize;
        if len < DMAR_HEADER_LEN || len > t.len() - off { return Err(IommuError::BadRecord); }
        let end = off + len;
        if ty == DMAR_TYPE_DRHD {
            if len < DRHD_LEN { return Err(IommuError::BadRecord); }
            validate_drhd_scopes(t, off + DRHD_LEN, end)?;
            push(&mut inv, IommuUnit { kind: IommuKind::IntelVtd, segment: le16(t, off + 6), register_base: le64(t, off + 8), include_all: t[off + 4] & DMAR_INCLUDE_ALL != 0 })?;
        }
        off = end;
    }
    if off != t.len() { return Err(IommuError::BadRecord); }
    Ok(inv)
}

fn publish(inv: IommuInventory) {
    if inv.unit_count == 0 { return; }
    if IOMMU_KIND.load(Ordering::Acquire) != IOMMU_KIND_NONE { return; }
    for i in 0..inv.unit_count {
        let u = inv.units[i];
        IOMMU_BASE[i].store(u.register_base, Ordering::Relaxed);
        IOMMU_SEGMENT[i].store(u.segment as u32, Ordering::Relaxed);
        IOMMU_FLAGS[i].store(u.include_all as u32, Ordering::Relaxed);
    }
    for i in 0..inv.amd_scope_count {
        let scope = inv.amd_scopes[i];
        AMD_SCOPE_UNIT[i].store(scope.unit_index as u32, Ordering::Relaxed);
        AMD_SCOPE_RANGE[i].store((scope.first_requester as u32) | ((scope.last_requester as u32) << 16), Ordering::Relaxed);
    }
    let kind = match inv.kind { IommuKind::AmdVi => IOMMU_KIND_AMD_VI, IommuKind::IntelVtd => IOMMU_KIND_INTEL_VTD };
    if IOMMU_KIND.compare_exchange(IOMMU_KIND_NONE, kind, Ordering::Release, Ordering::Acquire).is_ok() {
        AMD_SCOPE_COUNT.store(inv.amd_scope_count as u32, Ordering::Release);
        IOMMU_COUNT.store(inv.unit_count as u32, Ordering::Release);
    }
}

/// Count validated IOMMU units published during the ACPI walk.
/// # C: O(1)
pub fn iommu_unit_count() -> usize { IOMMU_COUNT.load(Ordering::Acquire) as usize }

/// Return one validated IOMMU unit by its boot-publication index.
/// # C: O(1)
pub fn iommu_unit(index: usize) -> Option<IommuUnit> {
    if index >= iommu_unit_count() { return None; }
    let kind = match IOMMU_KIND.load(Ordering::Acquire) {
        IOMMU_KIND_AMD_VI => IommuKind::AmdVi,
        IOMMU_KIND_INTEL_VTD => IommuKind::IntelVtd,
        _ => return None,
    };
    Some(IommuUnit {
        kind,
        segment: IOMMU_SEGMENT[index].load(Ordering::Relaxed) as u16,
        register_base: IOMMU_BASE[index].load(Ordering::Relaxed),
        include_all: IOMMU_FLAGS[index].load(Ordering::Relaxed) != 0,
    })
}

/// Return the sole translation unit for a PCI segment, refusing ambiguity.
/// Domain attachment must not select an IOMMU by requester ID alone. # C: O(N)
pub fn iommu_unit_for_segment(segment: u16) -> Option<IommuUnit> {
    let mut found = None;
    for index in 0..iommu_unit_count() {
        let unit = iommu_unit(index)?;
        if unit.segment != segment { continue; }
        if found.is_some() { return None; }
        found = Some(unit);
    }
    found
}

/// Return the unique AMD-Vi unit whose IVHD entries own this requester ID.
/// # C: O(N)
pub fn amd_vi_unit_for_requester(segment: u16, requester: u16) -> Option<IommuUnit> {
    if iommu_unit_count() == 0 || IOMMU_KIND.load(Ordering::Relaxed) != IOMMU_KIND_AMD_VI { return None; }
    let mut found = None;
    for index in 0..AMD_SCOPE_COUNT.load(Ordering::Acquire) as usize {
        let range = AMD_SCOPE_RANGE[index].load(Ordering::Relaxed);
        if requester < range as u16 || requester > (range >> 16) as u16 { continue; }
        let unit = iommu_unit(AMD_SCOPE_UNIT[index].load(Ordering::Relaxed) as usize)?;
        if unit.segment != segment { continue; }
        if found.is_some_and(|old: IommuUnit| old != unit) { return None; }
        found = Some(unit);
    }
    found
}

unsafe fn decode(pa: u64, hhdm_offset: u64, parse: fn(&[u8]) -> Result<IommuInventory, IommuError>, tag: &'static [u8]) {
    let p = (hhdm_offset.wrapping_add(pa)) as *const u8;
    // SAFETY: caller provides an HHDM-mapped standard ACPI header; offset 4 is within it.
    let len = unsafe { read_u32_le(p.add(4)) } as usize;
    if len > MAX_TABLE_LEN || len < IOMMU_TABLE_HEADER_LEN { alog_raw(b"[ERROR]    iommu: bad table length\n"); return; }
    // SAFETY: caller provides HHDM-backed ACPI memory; length was bounded to the firmware-table maximum above.
    let t = unsafe { core::slice::from_raw_parts(p, len) };
    match parse(t) {
        Ok(inv) => {
            alog_raw(b"[INFO]    "); alog_raw(tag); alog_raw(b" iommu_units="); alog_dec(inv.unit_count as u64); alog_raw(b"\n");
            for i in 0..inv.unit_count { alog_raw(b"[INFO]      iommu pa="); alog_hex(inv.units[i].register_base); alog_raw(b" seg="); alog_dec(inv.units[i].segment as u64); alog_raw(b"\n"); }
            publish(inv);
        }
        Err(_) => alog_raw(b"[ERROR]    iommu: rejected firmware table\n"),
    }
}

/// Decode and publish a checksum-validated Intel DMAR table.
/// # SAFETY: `pa` names an HHDM-backed ACPI table whose first header is readable.
/// # C: O(table bytes)
pub unsafe fn decode_dmar(pa: u64, hhdm_offset: u64) {
    // SAFETY: this wrapper preserves decode's HHDM-backed ACPI-table precondition.
    unsafe { decode(pa, hhdm_offset, parse_dmar, b"dmar") }
}

/// Decode and publish a checksum-validated AMD IVRS table.
/// # SAFETY: `pa` names an HHDM-backed ACPI table whose first header is readable.
/// # C: O(table bytes)
pub unsafe fn decode_ivrs(pa: u64, hhdm_offset: u64) {
    // SAFETY: this wrapper preserves decode's HHDM-backed ACPI-table precondition.
    unsafe { decode(pa, hhdm_offset, parse_ivrs, b"ivrs") }
}

#[cfg(test)]
mod tests;
