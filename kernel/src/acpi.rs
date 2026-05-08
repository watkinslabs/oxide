// Minimal ACPI RSDP read per ACPI 6.5 §5.2.5.3.
//
// Validates the "RSD PTR " signature, logs the revision and the
// system descriptor table pointer (RSDT for rev 0, XSDT for rev ≥ 2).
// Full RSDT/XSDT walking + table-by-table decode rides alongside the
// LAPIC/HPET bring-up that needs them.
//
// Logging is gated on `debug-acpi` per `04§4.0` (R06) via the
// `alog_*` helpers below — the *parsing* runs unconditionally so
// `cpu_topology` gets populated for SMP enumeration.

#[cfg(feature = "debug-acpi")]
#[inline] fn alog_raw(b: &[u8]) { klog::write_raw(b); }
#[cfg(not(feature = "debug-acpi"))]
#[inline] fn alog_raw(_b: &[u8]) {}

#[cfg(feature = "debug-acpi")]
#[inline] fn alog_dec(v: u64) { klog::write_dec_u64(v); }
#[cfg(not(feature = "debug-acpi"))]
#[inline] fn alog_dec(_v: u64) {}

#[cfg(feature = "debug-acpi")]
#[inline] fn alog_hex(v: u64) { klog::write_hex_u64(v); }
#[cfg(not(feature = "debug-acpi"))]
#[inline] fn alog_hex(_v: u64) {}

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
        alog_raw(b"[ERROR] xsdt: bad signature\n");
        return;
    }
    // SAFETY: caller-asserted ≥36 bytes readable; offset 4..8 well within.
    let length = unsafe { read_u32_le(p.add(4)) };
    if length < 36 || length > 4096 {
        // Bound the walk so a corrupt length doesn't run us off the
        // ACPI region.
        alog_raw(b"[ERROR] xsdt: implausible length\n");
        return;
    }
    let entry_count = ((length as usize) - 36) / 8;
    alog_raw(b"[INFO]  xsdt: ");
    alog_dec(entry_count as u64);
    alog_raw(b" tables\n");
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
        0  // we don't follow rev-0 RSDT in try_log_xsdt yet
    };
    alog_raw(b"\n");
    RsdpResult::Ok { revision, xsdt_pa }
}

/// Decode MADT (ACPI 6.5 §5.2.12) entry list and log per-entry info.
/// Handles common types only; unknown types are logged as `???`.
///
/// `pa` is the table's physical address (already-validated by the
/// XSDT walk); `hhdm_offset` is the Limine HHDM offset.
///
/// # SAFETY: caller asserts the table at `hhdm + pa` has a valid
/// ACPI SDT header + MADT entry list per its declared `length`.
/// # C: O(entries)
pub unsafe fn decode_madt(pa: u64, hhdm_offset: u64) {
    let p = (hhdm_offset.wrapping_add(pa)) as *const u8;
    // SAFETY: caller-asserted SDT header readable; offset 4..8 valid.
    let length = unsafe { read_u32_le(p.add(4)) } as usize;
    if length < 44 {
        alog_raw(b"[ERROR]    madt: too short\n");
        return;
    }
    // SAFETY: ≥44 bytes per length check; offset 36..40 valid.
    let lapic_pa = unsafe { read_u32_le(p.add(36)) } as u64;
    alog_raw(b"[INFO]    madt lapic_pa=");
    alog_hex(lapic_pa);
    alog_raw(b"\n");
    let mut off = 44usize;
    while off + 2 <= length {
        // SAFETY: per fn contract; we keep the walk strictly within `length` (verified above), so reading the 2-byte type+len header and any subsequent fields up to `elen` stays within the table's declared bounds.
        let (etype, elen) = unsafe {
            let t = core::ptr::read_volatile(p.add(off));
            let l = core::ptr::read_volatile(p.add(off + 1)) as usize;
            (t, l)
        };
        if elen < 2 || off + elen > length { break; }
        // SAFETY: same — `elen` was bounded against `length` above; every subsequent decode below stays within `[off, off+elen)`.
        unsafe {
            match etype {
                0 if elen >= 8 => {
                    let acpi_id = core::ptr::read_volatile(p.add(off + 2));
                    let apic_id = core::ptr::read_volatile(p.add(off + 3));
                    let flags   = read_u32_le(p.add(off + 4));
                    alog_raw(b"[INFO]      lapic acpi_id=");
                    alog_dec(acpi_id as u64);
                    alog_raw(b" apic_id=");
                    alog_dec(apic_id as u64);
                    alog_raw(b" flags=");
                    alog_hex(flags as u64);
                    alog_raw(b"\n");
                    // SAFETY: boot path; ACPI walk is single-threaded.
                    let _ = crate::cpu_topology::add_cpu(apic_id as u32, flags);
                }
                1 if elen >= 12 => {
                    let ioapic_id = core::ptr::read_volatile(p.add(off + 2));
                    let addr      = read_u32_le(p.add(off + 4));
                    let gsi_base  = read_u32_le(p.add(off + 8));
                    alog_raw(b"[INFO]      ioapic id=");
                    alog_dec(ioapic_id as u64);
                    alog_raw(b" pa=");
                    alog_hex(addr as u64);
                    alog_raw(b" gsi_base=");
                    alog_dec(gsi_base as u64);
                    alog_raw(b"\n");
                }
                5 if elen >= 12 => {
                    let addr = read_u64_le(p.add(off + 4));
                    alog_raw(b"[INFO]      lapic-override pa=");
                    alog_hex(addr);
                    alog_raw(b"\n");
                }
                9 if elen >= 16 => {
                    let x2apic_id = read_u32_le(p.add(off + 4));
                    let flags     = read_u32_le(p.add(off + 8));
                    let acpi_uid  = read_u32_le(p.add(off + 12));
                    alog_raw(b"[INFO]      x2apic id=");
                    alog_dec(x2apic_id as u64);
                    alog_raw(b" uid=");
                    alog_dec(acpi_uid as u64);
                    alog_raw(b" flags=");
                    alog_hex(flags as u64);
                    alog_raw(b"\n");
                    // SAFETY: boot path; ACPI walk is single-threaded.
                    let _ = crate::cpu_topology::add_cpu(x2apic_id, flags);
                }
                11 if elen >= 80 => {
                    let cpu_iface = read_u32_le(p.add(off + 4));
                    let acpi_uid  = read_u32_le(p.add(off + 8));
                    let flags     = read_u32_le(p.add(off + 12));
                    let mpidr     = read_u64_le(p.add(off + 60));
                    alog_raw(b"[INFO]      gicc iface=");
                    alog_dec(cpu_iface as u64);
                    alog_raw(b" uid=");
                    alog_dec(acpi_uid as u64);
                    alog_raw(b" mpidr=");
                    alog_hex(mpidr);
                    alog_raw(b"\n");
                    // ARM mpidr fits 24 low bits in v1 systems we target.
                    // SAFETY: boot path; ACPI walk is single-threaded.
                    let _ = crate::cpu_topology::add_cpu(mpidr as u32, flags);
                }
                12 if elen >= 24 => {
                    let gic_id   = read_u32_le(p.add(off + 4));
                    let phys     = read_u64_le(p.add(off + 8));
                    let version  = core::ptr::read_volatile(p.add(off + 20));
                    alog_raw(b"[INFO]      gicd id=");
                    alog_dec(gic_id as u64);
                    alog_raw(b" pa=");
                    alog_hex(phys);
                    alog_raw(b" v=");
                    alog_dec(version as u64);
                    alog_raw(b"\n");
                }
                14 if elen >= 16 => {
                    let phys   = read_u64_le(p.add(off + 4));
                    let length = read_u32_le(p.add(off + 12));
                    alog_raw(b"[INFO]      gicr pa=");
                    alog_hex(phys);
                    alog_raw(b" len=");
                    alog_hex(length as u64);
                    alog_raw(b"\n");
                }
                _ => {
                    alog_raw(b"[INFO]      madt-entry type=");
                    alog_dec(etype as u64);
                    alog_raw(b" len=");
                    alog_dec(elen as u64);
                    alog_raw(b"\n");
                }
            }
        }
        off += elen;
    }
}

/// Decode the HPET ACPI table (high-precision event timer) per
/// ACPI 6.5 §5.2.21 — 56 bytes total. Logs the MMIO base address.
///
/// # SAFETY: caller asserts the table at `hhdm + pa` has the standard
/// SDT header + 56 bytes of HPET layout (declared length checked first).
/// # C: O(1)
pub unsafe fn decode_hpet(pa: u64, hhdm_offset: u64) {
    let p = (hhdm_offset.wrapping_add(pa)) as *const u8;
    // SAFETY: caller-asserted SDT header readable; offset 4..8 within.
    let length = unsafe { read_u32_le(p.add(4)) } as usize;
    if length < 56 {
        alog_raw(b"[ERROR]    hpet: too short\n");
        return;
    }
    // SAFETY: length ≥ 56; offsets 36..52 are within the HPET-specific tail per ACPI 6.5 §5.2.21.
    unsafe {
        let block_id = read_u32_le(p.add(36));
        // GAS at offset 40: byte 40 address-space, 44..51 64-bit base.
        let addr_space = core::ptr::read_volatile(p.add(40));
        let base       = read_u64_le(p.add(44));
        let hpet_num   = core::ptr::read_volatile(p.add(52));
        alog_raw(b"[INFO]    hpet block_id=");
        alog_hex(block_id as u64);
        alog_raw(b" pa=");
        alog_hex(base);
        alog_raw(b" addr_space=");
        alog_dec(addr_space as u64);
        alog_raw(b" hpet_num=");
        alog_dec(hpet_num as u64);
        alog_raw(b"\n");
    }
}

/// Decode the SPCR ACPI table (Serial Port Console Redirection)
/// per Microsoft SPCR 4.0 — gives the firmware-elected console
/// UART's interface type + MMIO base. Useful to bypass the
/// hardcoded PL011 base on aarch64 once VMM lands.
///
/// # SAFETY: caller asserts standard SDT header + ≥80-byte SPCR
/// layout backed by HHDM-covered ACPI memory.
/// # C: O(1)
pub unsafe fn decode_spcr(pa: u64, hhdm_offset: u64) {
    let p = (hhdm_offset.wrapping_add(pa)) as *const u8;
    // SAFETY: caller-asserted SDT header readable; offset 4..8 within.
    let length = unsafe { read_u32_le(p.add(4)) } as usize;
    if length < 80 {
        alog_raw(b"[ERROR]    spcr: too short\n");
        return;
    }
    // SAFETY: length ≥ 80; offsets 36..52 within SPCR layout per Microsoft SPCR 4.0.
    unsafe {
        let iface  = core::ptr::read_volatile(p.add(36));
        // GAS at 40: byte 40 addr-space, 44..51 base.
        let addr_space = core::ptr::read_volatile(p.add(40));
        let base       = read_u64_le(p.add(44));
        let irq_type   = core::ptr::read_volatile(p.add(52));
        let gsi        = read_u32_le(p.add(54));
        let baud       = core::ptr::read_volatile(p.add(58));
        alog_raw(b"[INFO]    spcr iface=");
        alog_dec(iface as u64);
        alog_raw(b" pa=");
        alog_hex(base);
        alog_raw(b" addr_space=");
        alog_dec(addr_space as u64);
        alog_raw(b" irq_type=");
        alog_dec(irq_type as u64);
        alog_raw(b" gsi=");
        alog_dec(gsi as u64);
        alog_raw(b" baud=");
        alog_dec(baud as u64);
        alog_raw(b"\n");
    }
}

/// First-segment ECAM base PA published by `decode_mcfg`. Zero if
/// MCFG was absent / empty. The aarch64 PCI bring-up reads this to
/// know what to device-map.
pub static ECAM_BASE_PA: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(0);

/// Decode the MCFG ACPI table (PCI Express memory-mapped
/// configuration). Header is 36 SDT bytes + 8 reserved + an array
/// of 16-byte allocation entries. Each entry pins one ECAM region:
/// 64-bit base, 16-bit segment, start_bus, end_bus.
///
/// # SAFETY: caller asserts standard SDT header + payload backed by
/// HHDM-covered ACPI memory.
/// # C: O(entries)
pub unsafe fn decode_mcfg(pa: u64, hhdm_offset: u64) {
    let p = (hhdm_offset.wrapping_add(pa)) as *const u8;
    // SAFETY: caller-asserted SDT header readable; offset 4..8 within.
    let length = unsafe { read_u32_le(p.add(4)) } as usize;
    if length < 44 { return; }
    let body_off = 44usize;
    if length <= body_off { return; }
    let entries = (length - body_off) / 16;
    let mut i = 0usize;
    while i < entries {
        let off = body_off + i * 16;
        // SAFETY: bounded by `entries` derived from `length`; offsets within table per ACPI 6.5 §5.2.6 + PCI MCFG spec.
        unsafe {
            let base       = read_u64_le(p.add(off));
            let segment    = read_u32_le(p.add(off + 8)) as u16;
            let start_bus  = core::ptr::read_volatile(p.add(off + 10));
            let end_bus    = core::ptr::read_volatile(p.add(off + 11));
            // Publish the first segment's base for the aarch64 PCI
            // bring-up. Multi-segment systems would loop; QEMU virt
            // exposes a single segment so first-wins is fine for v1.
            if i == 0 {
                ECAM_BASE_PA.store(base, core::sync::atomic::Ordering::Release);
            }
            alog_raw(b"[INFO]    mcfg ecam pa=");
            alog_hex(base);
            alog_raw(b" segment=");
            alog_dec(segment as u64);
            alog_raw(b" bus=");
            alog_dec(start_bus as u64);
            alog_raw(b"..");
            alog_dec(end_bus as u64);
            alog_raw(b"\n");
        }
        i += 1;
    }
}

/// Decode the GTDT ACPI table (Generic Timer Description Table) per
/// ACPI 6.5 §5.2.25. Logs the four ARM EL1/EL2 timer GSIVs which a
/// future kernel timer-IRQ binder will route through GIC.
///
/// # SAFETY: caller asserts standard SDT header + ≥80-byte GTDT
/// layout backed by HHDM-covered ACPI memory.
/// # C: O(1)
pub unsafe fn decode_gtdt(pa: u64, hhdm_offset: u64) {
    let p = (hhdm_offset.wrapping_add(pa)) as *const u8;
    // SAFETY: caller-asserted SDT header readable; offset 4..8 within.
    let length = unsafe { read_u32_le(p.add(4)) } as usize;
    if length < 80 { return; }
    // SAFETY: length ≥ 80; offsets 36..76 within ACPI 6.5 §5.2.25 GTDT body.
    unsafe {
        let cnt_ctrl_base = read_u64_le(p.add(36));
        let sec_el1_gsiv  = read_u32_le(p.add(48));
        let nsec_el1_gsiv = read_u32_le(p.add(56));
        let virt_el1_gsiv = read_u32_le(p.add(64));
        let el2_gsiv      = read_u32_le(p.add(72));
        alog_raw(b"[INFO]    gtdt cnt_ctrl_pa=");
        alog_hex(cnt_ctrl_base);
        alog_raw(b" sec_el1=");
        alog_dec(sec_el1_gsiv as u64);
        alog_raw(b" nsec_el1=");
        alog_dec(nsec_el1_gsiv as u64);
        alog_raw(b" virt_el1=");
        alog_dec(virt_el1_gsiv as u64);
        alog_raw(b" el2=");
        alog_dec(el2_gsiv as u64);
        alog_raw(b"\n");
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
