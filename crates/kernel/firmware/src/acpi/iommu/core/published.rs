// Published immutable IOMMU inventory accessors and ACPI decode entrypoints.

use super::*;

fn scope_meta(scope: DmarScope) -> u64 {
    (scope.unit_index as u64) | ((scope.scope_type as u64) << 8) | ((scope.enumeration_id as u64) << 16)
        | ((scope.start_bus as u64) << 24) | ((scope.path_len as u64) << 32)
}

fn store_scope(meta: &AtomicU64, lo_slot: &AtomicU64, hi_slot: &AtomicU64, scope: DmarScope) {
    let mut lo = 0u64;
    let mut hi = 0u64;
    for j in 0..8 { lo |= (scope.path[j] as u64) << (j * 8); }
    for j in 0..8 { hi |= (scope.path[j + 8] as u64) << (j * 8); }
    meta.store(scope_meta(scope), Ordering::Relaxed);
    lo_slot.store(lo, Ordering::Relaxed);
    hi_slot.store(hi, Ordering::Relaxed);
}

fn load_scope(meta: u64, lo: u64, hi: u64) -> DmarScope {
    let mut path = [0u8; MAX_DMAR_PATH_BYTES];
    for j in 0..8 { path[j] = (lo >> (j * 8)) as u8; }
    for j in 0..8 { path[j + 8] = (hi >> (j * 8)) as u8; }
    DmarScope { unit_index: meta as u8, scope_type: (meta >> 8) as u8, enumeration_id: (meta >> 16) as u8,
        start_bus: (meta >> 24) as u8, path_len: (meta >> 32) as u8, path }
}

fn publish(inv: IommuInventory) {
    if inv.unit_count == 0 || IOMMU_KIND.load(Ordering::Acquire) != IOMMU_KIND_NONE { return; }
    for i in 0..inv.unit_count {
        let u = inv.units[i];
        IOMMU_BASE[i].store(u.register_base, Ordering::Relaxed);
        IOMMU_PAGES[i].store(u.register_pages, Ordering::Relaxed);
        IOMMU_SEGMENT[i].store(u.segment as u32, Ordering::Relaxed);
        IOMMU_FLAGS[i].store(u.include_all as u32, Ordering::Relaxed);
    }
    for i in 0..inv.amd_scope_count {
        let scope = inv.amd_scopes[i];
        AMD_SCOPE_UNIT[i].store(scope.unit_index as u32, Ordering::Relaxed);
        AMD_SCOPE_RANGE[i].store((scope.first_requester as u32) | ((scope.last_requester as u32) << 16), Ordering::Relaxed);
    }
    for i in 0..inv.amd_alias_count {
        let alias = inv.amd_aliases[i];
        AMD_ALIAS_UNIT[i].store(alias.unit_index as u32, Ordering::Relaxed);
        AMD_ALIAS_RANGE[i].store((alias.first_requester as u32) | ((alias.last_requester as u32) << 16), Ordering::Relaxed);
        AMD_ALIAS_TARGET[i].store(alias.canonical_requester as u32, Ordering::Relaxed);
    }
    for i in 0..inv.dmar_scope_count { store_scope(&DMAR_SCOPE_META[i], &DMAR_SCOPE_PATH_LO[i], &DMAR_SCOPE_PATH_HI[i], inv.dmar_scopes[i]); }
    for i in 0..inv.dmar_rmrr_count {
        let rmrr = inv.dmar_rmrrs[i];
        DMAR_RMRR_SEGMENT[i].store(rmrr.segment as u32, Ordering::Relaxed);
        DMAR_RMRR_BASE[i].store(rmrr.base, Ordering::Relaxed);
        DMAR_RMRR_END[i].store(rmrr.end, Ordering::Relaxed);
        for j in 0..rmrr.scope_count {
            let index = i * rmrr::MAX_RMRR_SCOPES + j;
            store_scope(&DMAR_RMRR_SCOPE_META[index], &DMAR_RMRR_SCOPE_PATH_LO[index], &DMAR_RMRR_SCOPE_PATH_HI[index], rmrr.scopes[j]);
        }
        DMAR_RMRR_SCOPE_COUNT[i].store(rmrr.scope_count as u32, Ordering::Relaxed);
    }
    let kind = match inv.kind { IommuKind::AmdVi => IOMMU_KIND_AMD_VI, IommuKind::IntelVtd => IOMMU_KIND_INTEL_VTD };
    // Publish every payload field before the kind's release-store makes this
    // inventory observable to readers.
    DMAR_FLAGS.store(inv.dmar_x2apic_opt_out as u32, Ordering::Relaxed);
    if IOMMU_KIND.compare_exchange(IOMMU_KIND_NONE, kind, Ordering::Release, Ordering::Acquire).is_ok() {
        AMD_SCOPE_COUNT.store(inv.amd_scope_count as u32, Ordering::Release);
        AMD_ALIAS_COUNT.store(inv.amd_alias_count as u32, Ordering::Release);
        DMAR_SCOPE_COUNT.store(inv.dmar_scope_count as u32, Ordering::Release);
        DMAR_RMRR_COUNT.store(inv.dmar_rmrr_count as u32, Ordering::Release);
        IOMMU_COUNT.store(inv.unit_count as u32, Ordering::Release);
    }
}

/// Return whether the DMAR table forbids x2APIC interrupt-remapping mode.
/// This is Linux's `DMAR_X2APIC_OPT_OUT` firmware policy gate. # C: O(1)
pub fn dmar_x2apic_opt_out() -> bool {
    IOMMU_KIND.load(Ordering::Acquire) == IOMMU_KIND_INTEL_VTD
        && DMAR_FLAGS.load(Ordering::Acquire) != 0
}

/// Count validated IOMMU units published during the ACPI walk. # C: O(1)
pub fn iommu_unit_count() -> usize { IOMMU_COUNT.load(Ordering::Acquire) as usize }

/// Return one validated IOMMU unit by its boot-publication index. # C: O(1)
pub fn iommu_unit(index: usize) -> Option<IommuUnit> {
    if index >= iommu_unit_count() { return None; }
    let kind = match IOMMU_KIND.load(Ordering::Acquire) { IOMMU_KIND_AMD_VI => IommuKind::AmdVi, IOMMU_KIND_INTEL_VTD => IommuKind::IntelVtd, _ => return None };
    Some(IommuUnit { kind, segment: IOMMU_SEGMENT[index].load(Ordering::Relaxed) as u16,
        register_base: IOMMU_BASE[index].load(Ordering::Relaxed), register_pages: IOMMU_PAGES[index].load(Ordering::Relaxed),
        include_all: IOMMU_FLAGS[index].load(Ordering::Relaxed) != 0 })
}

/// Return the sole translation unit for a PCI segment, refusing ambiguity. # C: O(N)
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

/// Return the unique AMD-Vi unit whose IVHD entries own this requester ID. # C: O(N)
pub fn amd_vi_unit_for_requester(segment: u16, requester: u16) -> Option<IommuUnit> {
    if iommu_unit_count() == 0 || IOMMU_KIND.load(Ordering::Relaxed) != IOMMU_KIND_AMD_VI { return None; }
    let mut alias_unit = None;
    for index in 0..AMD_ALIAS_COUNT.load(Ordering::Acquire) as usize {
        let range = AMD_ALIAS_RANGE[index].load(Ordering::Relaxed);
        if requester < range as u16 || requester > (range >> 16) as u16 { continue; }
        let unit = iommu_unit(AMD_ALIAS_UNIT[index].load(Ordering::Relaxed) as usize)?;
        if unit.segment != segment || alias_unit.is_some_and(|old: IommuUnit| old != unit) { return None; }
        alias_unit = Some(unit);
    }
    if alias_unit.is_some() { return alias_unit; }
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

/// Return the canonical requester ID for an IVHD alias, if this ID is aliased. # C: O(N)
pub fn amd_vi_alias_for_requester(segment: u16, requester: u16) -> Option<u16> {
    if IOMMU_KIND.load(Ordering::Relaxed) != IOMMU_KIND_AMD_VI { return None; }
    let mut target = None;
    for index in 0..AMD_ALIAS_COUNT.load(Ordering::Acquire) as usize {
        let range = AMD_ALIAS_RANGE[index].load(Ordering::Relaxed);
        if requester < range as u16 || requester > (range >> 16) as u16 { continue; }
        let unit = iommu_unit(AMD_ALIAS_UNIT[index].load(Ordering::Relaxed) as usize)?;
        if unit.segment != segment { continue; }
        let value = AMD_ALIAS_TARGET[index].load(Ordering::Relaxed) as u16;
        if target.is_some_and(|old| old != value) { return None; }
        target = Some(value);
    }
    target
}

/// Count published Intel DRHD device scopes. # C: O(1)
pub fn dmar_scope_count() -> usize { DMAR_SCOPE_COUNT.load(Ordering::Acquire) as usize }

/// Return one published Intel DRHD scope for PCI-route resolution. # C: O(1)
pub fn dmar_scope(index: usize) -> Option<DmarScope> {
    if index >= dmar_scope_count() || IOMMU_KIND.load(Ordering::Relaxed) != IOMMU_KIND_INTEL_VTD { return None; }
    Some(load_scope(DMAR_SCOPE_META[index].load(Ordering::Relaxed), DMAR_SCOPE_PATH_LO[index].load(Ordering::Relaxed), DMAR_SCOPE_PATH_HI[index].load(Ordering::Relaxed)))
}

/// Count published Intel device-reserved memory ranges. # C: O(1)
pub fn dmar_rmrr_count() -> usize { DMAR_RMRR_COUNT.load(Ordering::Acquire) as usize }

/// Return one published Intel device-reserved memory range and its scopes. # C: O(N_scopes)
pub fn dmar_rmrr(index: usize) -> Option<DmarRmrr> {
    if index >= dmar_rmrr_count() || IOMMU_KIND.load(Ordering::Relaxed) != IOMMU_KIND_INTEL_VTD { return None; }
    let scope_count = DMAR_RMRR_SCOPE_COUNT[index].load(Ordering::Relaxed) as usize;
    if scope_count > rmrr::MAX_RMRR_SCOPES { return None; }
    let empty = DmarScope { unit_index: DMAR_RMRR_SCOPE_UNIT, scope_type: 0, enumeration_id: 0, start_bus: 0, path_len: 0, path: [0; MAX_DMAR_PATH_BYTES] };
    let mut scopes = [empty; rmrr::MAX_RMRR_SCOPES];
    for j in 0..scope_count {
        let slot = index * rmrr::MAX_RMRR_SCOPES + j;
        scopes[j] = load_scope(DMAR_RMRR_SCOPE_META[slot].load(Ordering::Relaxed), DMAR_RMRR_SCOPE_PATH_LO[slot].load(Ordering::Relaxed), DMAR_RMRR_SCOPE_PATH_HI[slot].load(Ordering::Relaxed));
    }
    Some(DmarRmrr { segment: DMAR_RMRR_SEGMENT[index].load(Ordering::Relaxed) as u16,
        base: DMAR_RMRR_BASE[index].load(Ordering::Relaxed), end: DMAR_RMRR_END[index].load(Ordering::Relaxed), scopes, scope_count })
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
