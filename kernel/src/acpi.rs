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
    if rsdp_va == 0 {
        return RsdpStatus::Absent;
    }
    let p = rsdp_va as *const u8;
    // Signature.
    let mut sig = [0u8; 8];
    for i in 0..8 {
        // SAFETY: caller asserts ≥36 bytes readable.
        sig[i] = unsafe { core::ptr::read_volatile(p.add(i)) };
    }
    if &sig != b"RSD PTR " {
        klog::write_raw(b"[ERROR] rsdp: bad signature\n");
        return RsdpStatus::BadSignature;
    }
    // Revision (offset 15).
    // SAFETY: caller-asserted ≥36 bytes readable at `p`; offset 15 is well within the ACPI 1.0 RSDP block.
    let revision = unsafe { core::ptr::read_volatile(p.add(15)) };
    klog::write_raw(b"[INFO]  rsdp: signature ok, revision=");
    klog::write_dec_u64(revision as u64);
    if revision >= 2 {
        // XSDT address @ offset 24 (8 bytes LE).
        let mut xsdt = 0u64;
        for i in 0..8 {
            // SAFETY: same contract; rev ≥ 2 promises ≥ 36 bytes.
            let b = unsafe { core::ptr::read_volatile(p.add(24 + i)) } as u64;
            xsdt |= b << (i * 8);
        }
        klog::write_raw(b" xsdt=");
        klog::write_hex_u64(xsdt);
    } else {
        // RSDT address @ offset 16 (4 bytes LE).
        let mut rsdt = 0u32;
        for i in 0..4 {
            // SAFETY: rev 0 has 20-byte RSDP; offset 16..19 valid.
            let b = unsafe { core::ptr::read_volatile(p.add(16 + i)) } as u32;
            rsdt |= b << (i * 8);
        }
        klog::write_raw(b" rsdt=");
        klog::write_hex_u64(rsdt as u64);
    }
    klog::write_raw(b"\n");
    RsdpStatus::Logged
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
