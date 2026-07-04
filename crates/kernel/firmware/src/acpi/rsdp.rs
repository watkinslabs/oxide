use crate::acpi::log::{alog_dec, alog_hex, alog_raw};
use crate::acpi::read::{read_u32_le, read_u64_le};
use crate::acpi::tables::{decode_gtdt, decode_hpet, decode_madt, decode_mcfg, decode_spcr};
#[cfg(target_os = "oxide-kernel")]
use crate::acpi::tables::decode_iort;

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
    let mut sig = [0u8; 4];
    for i in 0..4 {
        // SAFETY: per fn contract, ≥36 bytes are readable at `p`.
        sig[i] = unsafe { core::ptr::read_volatile(p.add(i)) };
    }
    let entry_sz: usize = match &sig {
        b"XSDT" => 8,
        b"RSDT" => 4,
        _ => {
            alog_raw(b"[ERROR] xsdt: bad signature\n");
            return;
        }
    };
    // SAFETY: caller-asserted ≥36 bytes readable; offset 4..8 well within.
    let length = unsafe { read_u32_le(p.add(4)) };
    if length < 36 || length > 4096 {
        alog_raw(b"[ERROR] xsdt: implausible length\n");
        return;
    }
    let entry_count = ((length as usize) - 36) / entry_sz;
    alog_raw(b"[INFO]  xsdt: ");
    alog_dec(entry_count as u64);
    alog_raw(b" tables\n");
    let mut i = 0usize;
    while i < entry_count {
        let entry_pa = if entry_sz == 8 {
            // SAFETY: offset 36+i*8 is within the length-bounded XSDT; reads one 64-bit ACPI table pointer.
            unsafe { read_u64_le(p.add(36 + i * 8)) }
        } else {
            // SAFETY: offset 36+i*4 is within the length-bounded RSDT; reads one 32-bit ACPI table pointer.
            unsafe { read_u32_le(p.add(36 + i * 4)) as u64 }
        };
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
        alog_raw(b"[INFO]    acpi ");
        alog_raw(&tsig);
        alog_raw(b" pa=");
        alog_hex(entry_pa);
        alog_raw(b" len=");
        alog_dec(tlen as u64);
        alog_raw(b"\n");
        // SAFETY: per fn contract — HHDM covers ACPI memory; the
        // table's declared length is read inside each decoder and
        // checked before any further access.
        unsafe {
            match &tsig {
                b"APIC" => decode_madt(entry_pa, hhdm_offset),
                b"HPET" => decode_hpet(entry_pa, hhdm_offset),
                b"SPCR" => decode_spcr(entry_pa, hhdm_offset),
                b"MCFG" => decode_mcfg(entry_pa, hhdm_offset),
                b"GTDT" => decode_gtdt(entry_pa, hhdm_offset),
                #[cfg(target_os = "oxide-kernel")]
                b"IORT" => decode_iort(entry_pa, hhdm_offset),
                _       => {}
            }
        }
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
        alog_raw(b"[ERROR] rsdp: bad signature\n");
        return RsdpResult::BadSignature;
    }
    // SAFETY: caller-asserted ≥36 bytes readable at `p`; offset 15 within ACPI 1.0 RSDP.
    let revision = unsafe { core::ptr::read_volatile(p.add(15)) };
    alog_raw(b"[INFO]  rsdp: signature ok, revision=");
    alog_dec(revision as u64);
    let xsdt_pa = if revision >= 2 {
        // SAFETY: rev ≥ 2 RSDP is 36 bytes; offset 24..31 within.
        let v = unsafe { read_u64_le(p.add(24)) };
        alog_raw(b" xsdt=");
        alog_hex(v);
        v
    } else {
        // SAFETY: rev 0 RSDP has 20 bytes; offset 16..19 within.
        let v = unsafe { read_u32_le(p.add(16)) } as u64;
        alog_raw(b" rsdt=");
        alog_hex(v);
        v
    };
    alog_raw(b"\n");
    RsdpResult::Ok { revision, xsdt_pa }
}
