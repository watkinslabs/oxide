// DMAR/IVRS admission and immutable firmware inventory. This is the one
// source of x86 IOMMU-unit ownership; PCI and DMA consumers must read it,
// never rediscover tables or manufacture a second device-to-unit registry.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::acpi::log::{alog_dec, alog_hex, alog_raw};
use crate::acpi::read::read_u32_le;
mod rmrr;
mod published;
pub use rmrr::{DmarRmrr, MAX_RMRR_SCOPES as MAX_DMAR_RMRR_SCOPES};
pub use published::{amd_ivmd, amd_ivmd_count, amd_vi_alias_for_requester, amd_vi_special, amd_vi_special_count, amd_vi_unit_for_requester, decode_dmar, decode_ivrs,
    dmar_rmrr, dmar_rmrr_count, dmar_scope, dmar_scope_count, dmar_x2apic_opt_out, iommu_unit, iommu_unit_count,
    iommu_unit_for_segment};

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
pub const MAX_AMD_IVHD_ALIASES: usize = 256;
pub const MAX_AMD_IVMDS: usize = 64;
pub const MAX_AMD_SPECIALS: usize = 64;
pub const MAX_DMAR_SCOPES: usize = 256;
pub const MAX_DMAR_RMRRS: usize = 32;
pub const MAX_DMAR_PATH_BYTES: usize = 16;
pub const DMAR_RMRR_SCOPE_UNIT: u8 = u8::MAX;
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
const IVHD_DEV_SPECIAL: u8 = 0x48;
pub const AMD_SPECIAL_IOAPIC: u8 = 1;
pub const AMD_SPECIAL_HPET: u8 = 2;
const IVMD_TYPE_ALL: u8 = 0x20;
const IVMD_TYPE_SELECT: u8 = 0x21;
const IVMD_TYPE_RANGE: u8 = 0x22;
const IVMD_HEADER_LEN: usize = 32;
const IVMD_UNITY_MAP: u8 = 1;
const IVMD_IR: u8 = 1 << 1;
const IVMD_IW: u8 = 1 << 2;
const IVMD_EXCLUSION_RANGE: u8 = 1 << 3;
const DMAR_TYPE_DRHD: u16 = 0;
const DMAR_TYPE_RMRR: u16 = 1;
const DMAR_INCLUDE_ALL: u8 = 1;
const DMAR_X2APIC_OPT_OUT: u8 = 1 << 1;
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
    pub register_pages: u64,
    pub include_all: bool,
}

/// One AMD IVHD requester-id interval owned by a translation unit.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AmdIvhdScope {
    pub unit_index: u8,
    pub first_requester: u16,
    pub last_requester: u16,
}

/// One IVHD requester-id interval that shares one canonical requester ID.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AmdIvhdAlias {
    pub unit_index: u8,
    pub first_requester: u16,
    pub last_requester: u16,
    pub canonical_requester: u16,
}

/// One AMD IVRS IVMD unity/exclusion region and the requester IDs it covers.
/// Linux creates these before PCI DMA ownership is published. Both firmware
/// flags require an identity mapping: Linux treats exclusion ranges as RW
/// unity mappings to tolerate broken firmware with multiple exclusions.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AmdIvmd {
    pub segment: u16,
    pub first_requester: u16,
    pub last_requester: u16,
    pub base: u64,
    pub len: u64,
    pub read: bool,
    pub write: bool,
}

/// One IVHD special-device requester mapping.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AmdIvhdSpecial {
    pub unit_index: u8,
    pub kind: u8,
    pub id: u8,
    pub requester: u16,
}

/// One Intel DRHD device scope and its firmware PCI route chain.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DmarScope {
    pub unit_index: u8,
    pub scope_type: u8,
    pub enumeration_id: u8,
    pub start_bus: u8,
    pub path_len: u8,
    pub path: [u8; MAX_DMAR_PATH_BYTES],
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
    ScopePathTooLong,
}

/// Parsed architecture and its translation units.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IommuInventory {
    pub kind: IommuKind,
    pub dmar_x2apic_opt_out: bool,
    pub units: [IommuUnit; MAX_IOMMU_UNITS],
    pub unit_count: usize,
    pub amd_scopes: [AmdIvhdScope; MAX_AMD_IVHD_SCOPES],
    pub amd_scope_count: usize,
    pub amd_aliases: [AmdIvhdAlias; MAX_AMD_IVHD_ALIASES],
    pub amd_alias_count: usize,
    pub amd_ivmds: [AmdIvmd; MAX_AMD_IVMDS],
    pub amd_ivmd_count: usize,
    pub amd_specials: [AmdIvhdSpecial; MAX_AMD_SPECIALS],
    pub amd_special_count: usize,
    pub dmar_scopes: [DmarScope; MAX_DMAR_SCOPES],
    pub dmar_scope_count: usize,
    pub dmar_rmrrs: [DmarRmrr; MAX_DMAR_RMRRS],
    pub dmar_rmrr_count: usize,
}

static IOMMU_KIND: AtomicU32 = AtomicU32::new(IOMMU_KIND_NONE);
static IOMMU_COUNT: AtomicU32 = AtomicU32::new(0);
static DMAR_FLAGS: AtomicU32 = AtomicU32::new(0);
static IOMMU_BASE: [AtomicU64; MAX_IOMMU_UNITS] = [const { AtomicU64::new(0) }; MAX_IOMMU_UNITS];
static IOMMU_PAGES: [AtomicU64; MAX_IOMMU_UNITS] = [const { AtomicU64::new(0) }; MAX_IOMMU_UNITS];
static IOMMU_SEGMENT: [AtomicU32; MAX_IOMMU_UNITS] = [const { AtomicU32::new(0) }; MAX_IOMMU_UNITS];
static IOMMU_FLAGS: [AtomicU32; MAX_IOMMU_UNITS] = [const { AtomicU32::new(0) }; MAX_IOMMU_UNITS];
static AMD_SCOPE_UNIT: [AtomicU32; MAX_AMD_IVHD_SCOPES] = [const { AtomicU32::new(0) }; MAX_AMD_IVHD_SCOPES];
static AMD_SCOPE_RANGE: [AtomicU32; MAX_AMD_IVHD_SCOPES] = [const { AtomicU32::new(0) }; MAX_AMD_IVHD_SCOPES];
static AMD_SCOPE_COUNT: AtomicU32 = AtomicU32::new(0);
static AMD_ALIAS_UNIT: [AtomicU32; MAX_AMD_IVHD_ALIASES] = [const { AtomicU32::new(0) }; MAX_AMD_IVHD_ALIASES];
static AMD_ALIAS_RANGE: [AtomicU32; MAX_AMD_IVHD_ALIASES] = [const { AtomicU32::new(0) }; MAX_AMD_IVHD_ALIASES];
static AMD_ALIAS_TARGET: [AtomicU32; MAX_AMD_IVHD_ALIASES] = [const { AtomicU32::new(0) }; MAX_AMD_IVHD_ALIASES];
static AMD_ALIAS_COUNT: AtomicU32 = AtomicU32::new(0);
static AMD_IVMD_SEGMENT: [AtomicU32; MAX_AMD_IVMDS] = [const { AtomicU32::new(0) }; MAX_AMD_IVMDS];
static AMD_IVMD_RANGE: [AtomicU32; MAX_AMD_IVMDS] = [const { AtomicU32::new(0) }; MAX_AMD_IVMDS];
static AMD_IVMD_BASE: [AtomicU64; MAX_AMD_IVMDS] = [const { AtomicU64::new(0) }; MAX_AMD_IVMDS];
static AMD_IVMD_LEN: [AtomicU64; MAX_AMD_IVMDS] = [const { AtomicU64::new(0) }; MAX_AMD_IVMDS];
static AMD_IVMD_PERMS: [AtomicU32; MAX_AMD_IVMDS] = [const { AtomicU32::new(0) }; MAX_AMD_IVMDS];
static AMD_IVMD_COUNT: AtomicU32 = AtomicU32::new(0);
static AMD_SPECIAL_META: [AtomicU32; MAX_AMD_SPECIALS] = [const { AtomicU32::new(0) }; MAX_AMD_SPECIALS];
static AMD_SPECIAL_REQUESTER: [AtomicU32; MAX_AMD_SPECIALS] = [const { AtomicU32::new(0) }; MAX_AMD_SPECIALS];
static AMD_SPECIAL_COUNT: AtomicU32 = AtomicU32::new(0);
static DMAR_SCOPE_META: [AtomicU64; MAX_DMAR_SCOPES] = [const { AtomicU64::new(0) }; MAX_DMAR_SCOPES];
static DMAR_SCOPE_PATH_LO: [AtomicU64; MAX_DMAR_SCOPES] = [const { AtomicU64::new(0) }; MAX_DMAR_SCOPES];
static DMAR_SCOPE_PATH_HI: [AtomicU64; MAX_DMAR_SCOPES] = [const { AtomicU64::new(0) }; MAX_DMAR_SCOPES];
static DMAR_SCOPE_COUNT: AtomicU32 = AtomicU32::new(0);
static DMAR_RMRR_SEGMENT: [AtomicU32; MAX_DMAR_RMRRS] = [const { AtomicU32::new(0) }; MAX_DMAR_RMRRS];
static DMAR_RMRR_BASE: [AtomicU64; MAX_DMAR_RMRRS] = [const { AtomicU64::new(0) }; MAX_DMAR_RMRRS];
static DMAR_RMRR_END: [AtomicU64; MAX_DMAR_RMRRS] = [const { AtomicU64::new(0) }; MAX_DMAR_RMRRS];
static DMAR_RMRR_SCOPE_COUNT: [AtomicU32; MAX_DMAR_RMRRS] = [const { AtomicU32::new(0) }; MAX_DMAR_RMRRS];
static DMAR_RMRR_SCOPE_META: [AtomicU64; MAX_DMAR_RMRRS * rmrr::MAX_RMRR_SCOPES] = [const { AtomicU64::new(0) }; MAX_DMAR_RMRRS * rmrr::MAX_RMRR_SCOPES];
static DMAR_RMRR_SCOPE_PATH_LO: [AtomicU64; MAX_DMAR_RMRRS * rmrr::MAX_RMRR_SCOPES] = [const { AtomicU64::new(0) }; MAX_DMAR_RMRRS * rmrr::MAX_RMRR_SCOPES];
static DMAR_RMRR_SCOPE_PATH_HI: [AtomicU64; MAX_DMAR_RMRRS * rmrr::MAX_RMRR_SCOPES] = [const { AtomicU64::new(0) }; MAX_DMAR_RMRRS * rmrr::MAX_RMRR_SCOPES];
static DMAR_RMRR_COUNT: AtomicU32 = AtomicU32::new(0);

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

fn push_amd_alias(inv: &mut IommuInventory, unit_index: usize, first_requester: u16, last_requester: u16, canonical_requester: u16) -> Result<(), IommuError> {
    if first_requester > last_requester || inv.amd_alias_count == MAX_AMD_IVHD_ALIASES { return Err(IommuError::TooManyScopes); }
    inv.amd_aliases[inv.amd_alias_count] = AmdIvhdAlias { unit_index: unit_index as u8, first_requester, last_requester, canonical_requester };
    inv.amd_alias_count += 1;
    Ok(())
}

fn push_amd_ivmd(inv: &mut IommuInventory, segment: u16, first_requester: u16, last_requester: u16,
    base: u64, len: u64, read: bool, write: bool) -> Result<(), IommuError> {
    if first_requester > last_requester || len == 0 || inv.amd_ivmd_count == MAX_AMD_IVMDS { return Err(IommuError::TooManyScopes); }
    inv.amd_ivmds[inv.amd_ivmd_count] = AmdIvmd { segment, first_requester, last_requester, base, len, read, write };
    inv.amd_ivmd_count += 1;
    Ok(())
}

fn push_amd_special(inv: &mut IommuInventory, unit_index: usize, kind: u8, id: u8, requester: u16) -> Result<(), IommuError> {
    if inv.amd_special_count == MAX_AMD_SPECIALS || !matches!(kind, AMD_SPECIAL_IOAPIC | AMD_SPECIAL_HPET) { return Err(IommuError::BadRecord); }
    inv.amd_specials[inv.amd_special_count] = AmdIvhdSpecial { unit_index: unit_index as u8, kind, id, requester };
    inv.amd_special_count += 1;
    Ok(())
}

fn push_dmar_scope(inv: &mut IommuInventory, unit_index: usize, t: &[u8], off: usize, len: usize) -> Result<(), IommuError> {
    let path_len = len - DMAR_SCOPE_LEN;
    if path_len > MAX_DMAR_PATH_BYTES { return Err(IommuError::ScopePathTooLong); }
    if inv.dmar_scope_count == MAX_DMAR_SCOPES { return Err(IommuError::TooManyScopes); }
    let mut path = [0u8; MAX_DMAR_PATH_BYTES];
    path[..path_len].copy_from_slice(&t[off + DMAR_SCOPE_LEN..off + len]);
    inv.dmar_scopes[inv.dmar_scope_count] = DmarScope { unit_index: unit_index as u8, scope_type: t[off],
        enumeration_id: t[off + 4], start_bus: t[off + 5], path_len: path_len as u8, path };
    inv.dmar_scope_count += 1;
    Ok(())
}

fn parse_ivhd_entries(t: &[u8], start: usize, end: usize, unit_index: usize, inv: &mut IommuInventory) -> Result<(), IommuError> {
    let mut off = start;
    let mut range_start = None;
    let mut range_alias_target = None;
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
            IVHD_DEV_SELECT | IVHD_DEV_EXT_SELECT => push_amd_scope(inv, unit_index, requester, requester)?,
            IVHD_DEV_ALIAS => {
                push_amd_scope(inv, unit_index, requester, requester)?;
                push_amd_alias(inv, unit_index, requester, requester, le16(t, off + 6))?;
            }
            IVHD_DEV_SELECT_RANGE_START | IVHD_DEV_EXT_SELECT_RANGE => {
                if range_start.replace(requester).is_some() { return Err(IommuError::BadRecord); }
                range_alias_target = None;
            }
            IVHD_DEV_ALIAS_RANGE => {
                if range_start.replace(requester).is_some() { return Err(IommuError::BadRecord); }
                range_alias_target = Some(le16(t, off + 6));
            }
            IVHD_DEV_SPECIAL => {
                let ext = u32::from(t[off + 4]) | (u32::from(t[off + 5]) << 8)
                    | (u32::from(t[off + 6]) << 16) | (u32::from(t[off + 7]) << 24);
                push_amd_special(inv, unit_index, (ext >> 24) as u8, ext as u8, (ext >> 8) as u16)?;
            }
            IVHD_DEV_RANGE_END => {
                let first = range_start.take().ok_or(IommuError::BadRecord)?;
                push_amd_scope(inv, unit_index, first, requester)?;
                if let Some(target) = range_alias_target.take() { push_amd_alias(inv, unit_index, first, requester, target)?; }
            }
            _ => {}
        }
        off += len;
    }
    if off == end && range_start.is_none() && range_alias_target.is_none() { Ok(()) } else { Err(IommuError::BadRecord) }
}

/// Parse a complete AMD IVRS table without touching hardware.
/// # C: O(table bytes)
pub fn parse_ivrs(t: &[u8]) -> Result<IommuInventory, IommuError> {
    let t = checked_table(t, b"IVRS")?;
    let empty = IommuUnit { kind: IommuKind::AmdVi, segment: 0, register_base: 0, register_pages: 1, include_all: false };
    let empty_scope = AmdIvhdScope { unit_index: 0, first_requester: 0, last_requester: 0 };
    let empty_alias = AmdIvhdAlias { unit_index: 0, first_requester: 0, last_requester: 0, canonical_requester: 0 };
    let empty_ivmd = AmdIvmd { segment: 0, first_requester: 0, last_requester: 0, base: 0, len: 0, read: false, write: false };
    let empty_special = AmdIvhdSpecial { unit_index: 0, kind: 0, id: 0, requester: 0 };
    let empty_dmar_scope = DmarScope { unit_index: 0, scope_type: 0, enumeration_id: 0, start_bus: 0, path_len: 0, path: [0; MAX_DMAR_PATH_BYTES] };
    let empty_rmrr = DmarRmrr { segment: 0, base: 0, end: 0, scopes: [empty_dmar_scope; rmrr::MAX_RMRR_SCOPES], scope_count: 0 };
    let mut inv = IommuInventory { kind: IommuKind::AmdVi, dmar_x2apic_opt_out: false, units: [empty; MAX_IOMMU_UNITS], unit_count: 0,
        amd_scopes: [empty_scope; MAX_AMD_IVHD_SCOPES], amd_scope_count: 0,
        amd_aliases: [empty_alias; MAX_AMD_IVHD_ALIASES], amd_alias_count: 0,
        amd_ivmds: [empty_ivmd; MAX_AMD_IVMDS], amd_ivmd_count: 0, amd_specials: [empty_special; MAX_AMD_SPECIALS], amd_special_count: 0,
        dmar_scopes: [empty_dmar_scope; MAX_DMAR_SCOPES], dmar_scope_count: 0, dmar_rmrrs: [empty_rmrr; MAX_DMAR_RMRRS], dmar_rmrr_count: 0 };
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
            push(&mut inv, IommuUnit { kind: IommuKind::AmdVi, segment: le16(t, off + 16), register_base: le64(t, off + 8), register_pages: 1, include_all: false })?;
        } else if matches!(ty, IVMD_TYPE_ALL | IVMD_TYPE_SELECT | IVMD_TYPE_RANGE) {
            if len != IVMD_HEADER_LEN { return Err(IommuError::BadRecord); }
            let flags = t[off + 1];
            if flags & (IVMD_UNITY_MAP | IVMD_EXCLUSION_RANGE) != 0 {
                let first = match ty { IVMD_TYPE_ALL => 0, _ => le16(t, off + 4) };
                let last = match ty { IVMD_TYPE_ALL => u16::MAX, IVMD_TYPE_SELECT => first, _ => le16(t, off + 6) };
                // Match Linux `init_unity_map_range()`: IVMD addresses are
                // converted to page intervals before their PTEs are built.
                let base = le64(t, off + 16).checked_add(0xfff).map(|v| v & !0xfff).ok_or(IommuError::BadRecord)?;
                let len = le64(t, off + 24).checked_add(0xfff).map(|v| v & !0xfff).ok_or(IommuError::BadRecord)?;
                if len == 0 || base.checked_add(len).is_none() { return Err(IommuError::BadRecord); }
                let (read, write) = if flags & IVMD_EXCLUSION_RANGE != 0 { (true, true) }
                    else { (flags & IVMD_IR != 0, flags & IVMD_IW != 0) };
                push_amd_ivmd(&mut inv, le16(t, off + 8), first, last, base, len, read, write)?;
            }
        }
        off = end;
    }
    if off != t.len() { return Err(IommuError::BadRecord); }
    Ok(inv)
}

fn parse_drhd_scopes(t: &[u8], start: usize, end: usize, unit_index: usize, inv: &mut IommuInventory) -> Result<(), IommuError> {
    let mut off = start;
    while off < end {
        if end - off < DMAR_SCOPE_LEN { return Err(IommuError::BadRecord); }
        let len = t[off + 1] as usize;
        if len < DMAR_SCOPE_LEN || len > end - off || (len - DMAR_SCOPE_LEN) % 2 != 0 { return Err(IommuError::BadRecord); }
        push_dmar_scope(inv, unit_index, t, off, len)?;
        off += len;
    }
    if off == end { Ok(()) } else { Err(IommuError::BadRecord) }
}

/// Parse a complete Intel DMAR table without touching hardware.
/// # C: O(table bytes)
pub fn parse_dmar(t: &[u8]) -> Result<IommuInventory, IommuError> {
    let t = checked_table(t, b"DMAR")?;
    if t[ACPI_HEADER_LEN] < DMAR_MIN_HOST_ADDRESS_WIDTH { return Err(IommuError::BadRecord); }
    let empty = IommuUnit { kind: IommuKind::IntelVtd, segment: 0, register_base: 0, register_pages: 1, include_all: false };
    let empty_scope = AmdIvhdScope { unit_index: 0, first_requester: 0, last_requester: 0 };
    let empty_alias = AmdIvhdAlias { unit_index: 0, first_requester: 0, last_requester: 0, canonical_requester: 0 };
    let empty_ivmd = AmdIvmd { segment: 0, first_requester: 0, last_requester: 0, base: 0, len: 0, read: false, write: false };
    let empty_special = AmdIvhdSpecial { unit_index: 0, kind: 0, id: 0, requester: 0 };
    let empty_dmar_scope = DmarScope { unit_index: 0, scope_type: 0, enumeration_id: 0, start_bus: 0, path_len: 0, path: [0; MAX_DMAR_PATH_BYTES] };
    let empty_rmrr = DmarRmrr { segment: 0, base: 0, end: 0, scopes: [empty_dmar_scope; rmrr::MAX_RMRR_SCOPES], scope_count: 0 };
    let mut inv = IommuInventory { kind: IommuKind::IntelVtd,
        dmar_x2apic_opt_out: t[ACPI_HEADER_LEN + 1] & DMAR_X2APIC_OPT_OUT != 0,
        units: [empty; MAX_IOMMU_UNITS], unit_count: 0,
        amd_scopes: [empty_scope; MAX_AMD_IVHD_SCOPES], amd_scope_count: 0,
        amd_aliases: [empty_alias; MAX_AMD_IVHD_ALIASES], amd_alias_count: 0,
        amd_ivmds: [empty_ivmd; MAX_AMD_IVMDS], amd_ivmd_count: 0, amd_specials: [empty_special; MAX_AMD_SPECIALS], amd_special_count: 0,
        dmar_scopes: [empty_dmar_scope; MAX_DMAR_SCOPES], dmar_scope_count: 0, dmar_rmrrs: [empty_rmrr; MAX_DMAR_RMRRS], dmar_rmrr_count: 0 };
    let mut off = IOMMU_TABLE_HEADER_LEN;
    while off < t.len() {
        if t.len() - off < DMAR_HEADER_LEN { return Err(IommuError::BadRecord); }
        let ty = le16(t, off);
        let len = le16(t, off + 2) as usize;
        if len < DMAR_HEADER_LEN || len > t.len() - off { return Err(IommuError::BadRecord); }
        let end = off + len;
        if ty == DMAR_TYPE_DRHD {
            if len < DRHD_LEN { return Err(IommuError::BadRecord); }
            parse_drhd_scopes(t, off + DRHD_LEN, end, inv.unit_count, &mut inv)?;
            let Some(register_pages) = 1u64.checked_shl(u32::from(t[off + 5])) else { return Err(IommuError::BadRecord); };
            push(&mut inv, IommuUnit { kind: IommuKind::IntelVtd, segment: le16(t, off + 6), register_base: le64(t, off + 8), register_pages, include_all: t[off + 4] & DMAR_INCLUDE_ALL != 0 })?;
        } else if ty == DMAR_TYPE_RMRR { rmrr::parse(t, off, end, &mut inv)?; }
        off = end;
    }
    if off != t.len() { return Err(IommuError::BadRecord); }
    Ok(inv)
}
