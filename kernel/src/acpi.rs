// Minimal ACPI RSDP read per ACPI 6.5 §5.2.5.3.
//
// Validates the "RSD PTR " signature, logs the revision and the
// system descriptor table pointer (RSDT for rev 0, XSDT for rev ≥ 2).
// Full RSDT/XSDT walking + table-by-table decode rides alongside the
// LAPIC/HPET bring-up that needs them.

/// Outcome of `try_log_rsdp` for callers that want to check.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RsdpStatus {
    /// `rsdp_pa == 0` — bootloader didn't surface ACPI.
    Absent,
    /// First 8 bytes are not `RSD PTR `.
    BadSignature,
    /// Read OK; emitted the summary line.
    Logged,
}

/// Read 4 bytes at `p` and return as a little-endian `u32`.
/// # SAFETY: caller asserts ≥4 bytes readable at `p`.
unsafe fn read_u32_le(p: *const u8) -> u32 {
    let mut v = 0u32;
    let mut i = 0u32;
    while i < 4 {
        // SAFETY: caller asserts ≥4 bytes readable; offset i < 4.
        let b = unsafe { core::ptr::read_volatile(p.add(i as usize)) } as u32;
        v |= b << (i * 8);
        i += 1;
    }
    v
}

/// Read 8 bytes at `p` and return as a little-endian `u64`.
/// # SAFETY: caller asserts ≥8 bytes readable at `p`.
unsafe fn read_u64_le(p: *const u8) -> u64 {
    let mut v = 0u64;
    let mut i = 0u32;
    while i < 8 {
        // SAFETY: caller asserts ≥8 bytes readable; offset i < 8.
        let b = unsafe { core::ptr::read_volatile(p.add(i as usize)) } as u64;
        v |= b << (i * 8);
        i += 1;
    }
    v
}

/// Walk a Limine-supplied XSDT and log each table signature + length.
///
/// `xsdt_pa` is the physical address from the RSDP (rev ≥ 2);
/// `hhdm_offset` is `info.hhdm_offset` so we can dereference.
///
/// # SAFETY: caller asserts (a) `xsdt_pa` is a real ACPI XSDT phys
/// address with HHDM-covered backing, (b) `hhdm_offset` is the live
/// HHDM mapping for the bootloader's RAM. Bootloader-owned ACPI
/// memory survives past kernel handoff per `36§3`.
/// # C: O(table count)
/// # Ctx: pre-init, single-CPU
pub unsafe fn try_log_xsdt(xsdt_pa: u64, hhdm_offset: u64) {
    if xsdt_pa == 0 || hhdm_offset == 0 {
        return;
    }
    let p = (hhdm_offset.wrapping_add(xsdt_pa)) as *const u8;
    // Standard SDT header: 4-byte sig + 4-byte length + 1B rev + 1B
    // chksum + 6B oemid + 8B oem_table + 4B oem_rev + 4B creator_id
    // + 4B creator_rev = 36 bytes.
    let mut sig = [0u8; 4];
    for i in 0..4 {
        // SAFETY: per fn contract, ≥36 bytes are readable at `p`.
        sig[i] = unsafe { core::ptr::read_volatile(p.add(i)) };
    }
    if &sig != b"XSDT" {
        klog::write_raw(b"[ERROR] xsdt: bad signature\n");
        return;
    }
    // SAFETY: caller-asserted ≥36 bytes readable; offset 4..8 well within.
    let length = unsafe { read_u32_le(p.add(4)) };
    if length < 36 || length > 4096 {
        // Bound the walk so a corrupt length doesn't run us off the
        // ACPI region.
        klog::write_raw(b"[ERROR] xsdt: implausible length\n");
        return;
    }
    let entry_count = ((length as usize) - 36) / 8;
    klog::write_raw(b"[INFO]  xsdt: ");
    klog::write_dec_u64(entry_count as u64);
    klog::write_raw(b" tables\n");
    let mut i = 0usize;
    while i < entry_count {
        // SAFETY: pointer offset is within the XSDT (length-bounded).
        let entry_pa = unsafe { read_u64_le(p.add(36 + i * 8)) };
        if entry_pa == 0 { i += 1; continue; }
        let tp = (hhdm_offset.wrapping_add(entry_pa)) as *const u8;
        let mut tsig = [0u8; 4];
        for j in 0..4 {
            // SAFETY: each XSDT pointer references a standard ACPI
            // SDT (≥36-byte header) per ACPI 6.5 §5.2.6.
            tsig[j] = unsafe { core::ptr::read_volatile(tp.add(j)) };
        }
        // SAFETY: same; offset 4..8 within the SDT header.
        let tlen = unsafe { read_u32_le(tp.add(4)) };
        klog::write_raw(b"[INFO]    acpi ");
        klog::write_raw(&tsig);
        klog::write_raw(b" pa=");
        klog::write_hex_u64(entry_pa);
        klog::write_raw(b" len=");
        klog::write_dec_u64(tlen as u64);
        klog::write_raw(b"\n");
        i += 1;
    }
}

/// Read an HHDM-mapped RSDP pointer, validate, log a one-line summary.
///
/// `rsdp_va` is the kernel-VA pointer Limine surfaced
/// (`info.rsdp_pa`); 0 means absent. We don't compute the checksum
/// here — the goal is "does ACPI exist and is the pointer sane?",
/// not full validation.
///
/// # SAFETY: caller asserts `rsdp_va` is either 0 or a kernel-VA
/// pointer to ≥ 36 bytes of bootloader-owned ACPI memory (true for
/// any non-null Limine RSDP response).
/// # C: O(1)
/// # Ctx: pre-init, single-CPU
pub unsafe fn try_log_rsdp(rsdp_va: u64) -> RsdpStatus {
    // SAFETY: per fn contract — caller asserted the bootloader-supplied RSDP/XSDT pointers are live.
    match unsafe { parse_and_log_rsdp(rsdp_va) } {
        RsdpResult::Absent       => RsdpStatus::Absent,
        RsdpResult::BadSignature => RsdpStatus::BadSignature,
        RsdpResult::Ok { .. }    => RsdpStatus::Logged,
    }
}

/// Internal parse result so the kernel can chain RSDP → XSDT walk.
#[allow(dead_code)]
enum RsdpResult {
    Absent,
    BadSignature,
    Ok { revision: u8, xsdt_pa: u64 },
}

/// Parse RSDP and emit the one-line summary. Returns the parsed
/// fields; `xsdt_pa == 0` for rev 0 RSDPs (RSDT instead — currently
/// not wired into `try_log_xsdt`).
unsafe fn parse_and_log_rsdp(rsdp_va: u64) -> RsdpResult {
    if rsdp_va == 0 {
        return RsdpResult::Absent;
    }
    let p = rsdp_va as *const u8;
    let mut sig = [0u8; 8];
    for i in 0..8 {
        // SAFETY: caller asserts ≥36 bytes readable at `p`.
        sig[i] = unsafe { core::ptr::read_volatile(p.add(i)) };
    }
    if &sig != b"RSD PTR " {
        klog::write_raw(b"[ERROR] rsdp: bad signature\n");
        return RsdpResult::BadSignature;
    }
    // SAFETY: caller-asserted ≥36 bytes readable at `p`; offset 15 within ACPI 1.0 RSDP.
    let revision = unsafe { core::ptr::read_volatile(p.add(15)) };
    klog::write_raw(b"[INFO]  rsdp: signature ok, revision=");
    klog::write_dec_u64(revision as u64);
    let xsdt_pa = if revision >= 2 {
        // SAFETY: rev ≥ 2 RSDP is 36 bytes; offset 24..31 within.
        let v = unsafe { read_u64_le(p.add(24)) };
        klog::write_raw(b" xsdt=");
        klog::write_hex_u64(v);
        v
    } else {
        // SAFETY: rev 0 RSDP has 20 bytes; offset 16..19 within.
        let v = unsafe { read_u32_le(p.add(16)) } as u64;
        klog::write_raw(b" rsdt=");
        klog::write_hex_u64(v);
        0  // we don't follow rev-0 RSDT in try_log_xsdt yet
    };
    klog::write_raw(b"\n");
    RsdpResult::Ok { revision, xsdt_pa }
}

/// Parse RSDP, then if XSDT is present, walk and log each table.
/// Convenience wrapper around `parse_and_log_rsdp` + `try_log_xsdt`.
///
/// # SAFETY: same contract as `try_log_rsdp` for `rsdp_va`;
/// `hhdm_offset` is the live Limine HHDM offset.
/// # C: O(table count)
pub unsafe fn try_log_acpi(rsdp_va: u64, hhdm_offset: u64) {
    // SAFETY: per fn contract — caller asserted the bootloader-supplied RSDP/XSDT pointers are live.
    let res = unsafe { parse_and_log_rsdp(rsdp_va) };
    if let RsdpResult::Ok { xsdt_pa, .. } = res {
        if xsdt_pa != 0 {
            // SAFETY: per fn contract; xsdt_pa just decoded from a
            // valid ACPI 2.0+ RSDP.
            unsafe { try_log_xsdt(xsdt_pa, hhdm_offset); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_returns_absent() {
        // SAFETY: rsdp_va=0 path returns immediately; pointer is never dereferenced.
        assert_eq!(unsafe { try_log_rsdp(0) }, RsdpStatus::Absent);
    }

    #[test]
    fn rsdp_status_distinct() {
        assert_ne!(RsdpStatus::Absent, RsdpStatus::BadSignature);
        assert_ne!(RsdpStatus::Logged, RsdpStatus::BadSignature);
    }
}
