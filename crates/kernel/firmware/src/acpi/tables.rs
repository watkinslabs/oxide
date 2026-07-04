use crate::acpi::log::{alog_dec, alog_hex, alog_raw};
use crate::acpi::read::{read_u32_le, read_u64_le};

/// First-segment ECAM base PA published by `decode_mcfg`. Zero if
/// MCFG was absent / empty. The aarch64 PCI bring-up reads this to
/// know what to device-map.
pub static ECAM_BASE_PA: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(0);

/// Physical base of the first GICv2m MSI frame discovered via MADT
/// type-13 entries (ACPI 6.4 Table 5.50). Zero = no GICv2m frame
/// reported (could be GICv3 ITS-only or x86, or pre-MADT-walk).
/// Per-arch MSI delivery wiring (F36+) reads this to compute
/// MSI message addresses on aarch64.
pub static GIC_MSI_FRAME_PA: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(0);

/// Physical base of the first GICv3 ITS discovered via MADT type-15
/// entries (ACPI 6.4 Table 5.51). Zero = no ITS reported (GICv2m or
/// pre-MADT-walk). The ITS driver (`its.rs`) reads this to map the
/// GITS_* registers and post commands; MSI delivery on GICv3 routes
/// device writes to `GITS_TRANSLATER` at `pa + 0x0040`.
pub static GIC_ITS_PA: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(0);

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
                    let _ = crate::fire_add_cpu(apic_id as u32, flags);
                }
                1 if elen >= 12 => {
                    let ioapic_id = core::ptr::read_volatile(p.add(off + 2));
                    let addr      = read_u32_le(p.add(off + 4));
                    let gsi_base  = read_u32_le(p.add(off + 8));
                    crate::set_ioapic(addr, gsi_base);
                    alog_raw(b"[INFO]      ioapic id=");
                    alog_dec(ioapic_id as u64);
                    alog_raw(b" pa=");
                    alog_hex(addr as u64);
                    alog_raw(b" gsi_base=");
                    alog_dec(gsi_base as u64);
                    alog_raw(b"\n");
                }
                2 if elen >= 10 => {
                    let source = core::ptr::read_volatile(p.add(off + 3));
                    let gsi    = read_u32_le(p.add(off + 4));
                    let flags  = (core::ptr::read_volatile(p.add(off + 8)) as u16)
                        | ((core::ptr::read_volatile(p.add(off + 9)) as u16) << 8);
                    crate::set_irq_override(source, gsi, flags);
                    alog_raw(b"[INFO]      irq-override src=");
                    alog_dec(source as u64);
                    alog_raw(b" gsi=");
                    alog_dec(gsi as u64);
                    alog_raw(b" flags=");
                    alog_hex(flags as u64);
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
                    let _ = crate::fire_add_cpu(x2apic_id, flags);
                }
                11 if elen >= 80 => {
                    let cpu_iface = read_u32_le(p.add(off + 4));
                    let acpi_uid  = read_u32_le(p.add(off + 8));
                    let flags     = read_u32_le(p.add(off + 12));
                    let mpidr     = read_u64_le(p.add(off + 68));
                    alog_raw(b"[INFO]      gicc iface=");
                    alog_dec(cpu_iface as u64);
                    alog_raw(b" uid=");
                    alog_dec(acpi_uid as u64);
                    alog_raw(b" mpidr=");
                    alog_hex(mpidr);
                    alog_raw(b"\n");
                    let _ = crate::fire_add_cpu(mpidr as u32, flags);
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
                13 if elen >= 24 => {
                    let frame_id  = read_u32_le(p.add(off + 4));
                    let phys      = read_u64_le(p.add(off + 8));
                    let flags     = read_u32_le(p.add(off + 16));
                    alog_raw(b"[INFO]      gic-msi-frame id=");
                    alog_dec(frame_id as u64);
                    alog_raw(b" pa=");
                    alog_hex(phys);
                    alog_raw(b" flags=");
                    alog_hex(flags as u64);
                    alog_raw(b"\n");
                    GIC_MSI_FRAME_PA.compare_exchange(
                        0, phys,
                        core::sync::atomic::Ordering::Release,
                        core::sync::atomic::Ordering::Relaxed,
                    ).ok();
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
                15 if elen >= 20 => {
                    let its_id = read_u32_le(p.add(off + 4));
                    let phys   = read_u64_le(p.add(off + 8));
                    alog_raw(b"[INFO]      gic-its id=");
                    alog_dec(its_id as u64);
                    alog_raw(b" pa=");
                    alog_hex(phys);
                    alog_raw(b"\n");
                    GIC_ITS_PA.compare_exchange(
                        0, phys,
                        core::sync::atomic::Ordering::Release,
                        core::sync::atomic::Ordering::Relaxed,
                    ).ok();
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
        if base != 0 { crate::set_spcr(base, addr_space, gsi); }
    }
}

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

/// Decode the IORT (I/O Remapping Table) per ACPI 6.4 §5.2.30.
///
/// # SAFETY: caller asserted `iort_pa` came from a valid XSDT entry
/// and is HHDM-mapped contiguously for the table's declared length.
/// # C: O(num_nodes)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn decode_iort(iort_pa: u64, hhdm_offset: u64) {
    let p = (hhdm_offset + iort_pa) as *const u8;
    // SAFETY: iort_pa lies in HHDM-mapped ACPI memory; the SDT length
    // field at +0x04 covers the trailing IORT header + nodes.
    let sdt_len = unsafe { read_u32_le(p.add(4)) } as usize;
    if sdt_len < 48 {
        alog_raw(b"[INFO]    iort: too short\n");
        return;
    }
    // SAFETY: HHDM-mapped IORT, sdt_len verified >= 48 above; reads at u32-aligned offsets 36/40 stay in-bounds.
    let num_nodes = unsafe { read_u32_le(p.add(36)) } as usize;
    // SAFETY: same HHDM-mapped IORT region; offset 40 is u32-aligned and within sdt_len.
    let node_off0 = unsafe { read_u32_le(p.add(40)) } as usize;
    alog_raw(b"[INFO]    iort num_nodes=");
    alog_dec(num_nodes as u64);
    alog_raw(b" first_node_off=");
    alog_hex(node_off0 as u64);
    alog_raw(b"\n");
    let mut off = node_off0;
    let mut idx = 0usize;
    while idx < num_nodes && off + 16 <= sdt_len {
        // SAFETY: HHDM-mapped IORT region; loop guard ensures off+16 <= sdt_len so this u8 read is in-bounds.
        let nty = unsafe { core::ptr::read_volatile(p.add(off)) };
        // SAFETY: same HHDM-mapped IORT region; off+1 < off+16 <= sdt_len verified by loop guard.
        let nlen_lo = unsafe { core::ptr::read_volatile(p.add(off + 1)) } as usize;
        // SAFETY: same HHDM-mapped IORT region; off+2 < off+16 <= sdt_len verified by loop guard.
        let nlen_hi = unsafe { core::ptr::read_volatile(p.add(off + 2)) } as usize;
        let nlen = nlen_lo | (nlen_hi << 8);
        if nlen < 16 || off + nlen > sdt_len { break; }
        let label: &[u8] = match nty {
            0 => b"ITS-group",
            1 => b"named-component",
            2 => b"root-complex",
            3 => b"SMMUv1/v2",
            4 => b"SMMUv3",
            5 => b"PMCG",
            6 => b"memory-range",
            _ => b"unknown",
        };
        alog_raw(b"[INFO]    iort-node type=");
        alog_dec(nty as u64);
        alog_raw(b" (");
        alog_raw(label);
        alog_raw(b") len=");
        alog_dec(nlen as u64);
        alog_raw(b"\n");
        off += nlen;
        idx += 1;
    }
}
