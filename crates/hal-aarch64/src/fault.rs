// EL1 exception printer per `21§5`. Called from
// `oxide_default_vector_handler` (asm in `vbar.rs`) with the three
// system registers most useful for triage:
//
//   x0 = ESR_EL1   exception syndrome (cause + ISS)
//   x1 = FAR_EL1   fault address (data/instruction abort)
//   x2 = ELR_EL1   return address (instruction at exception)
//
// Emits a one-line summary via `klog::write_raw` then returns; the
// asm caller halts via `wfi` after `bl`.

// Per `04§4.0` (R06): emit-path call sites gated under `debug-irq`.
// Default builds halt silently on a fault; the diagnostic dump rides
// the same gate as the rest of the IRQ/exception trace surface.
#[cfg(feature = "debug-irq")]
macro_rules! debug_irq { ($($t:tt)*) => { $($t)* } }
#[cfg(not(feature = "debug-irq"))]
macro_rules! debug_irq { ($($t:tt)*) => {} }

/// Rust-side EL1 fault printer.
///
/// # SAFETY: caller is the shared default vector handler. We only
/// read function arguments; klog uses the global byte sink.
/// # C: O(constant)
/// # Ctx: exception, IRQ-off (DAIF set by handler)
#[no_mangle]
pub unsafe extern "C" fn oxide_fault_print_rust(esr: u64, far: u64, elr: u64) {
    debug_irq! {
        let ec = ((esr >> 26) & 0x3f) as u32;        // ESR_EL1.EC bits 26..31
        let iss = esr & 0xff_ffff;                   // ESR_EL1.ISS bits 0..24
        klog::write_raw(b"[FAULT] esr=");
        klog::write_hex_u64(esr);
        klog::write_raw(b" ec=");
        klog::write_hex_u64(ec as u64);
        klog::write_raw(b" (");
        klog::write_raw(ec_label(ec));
        klog::write_raw(b") far=");
        klog::write_hex_u64(far);
        klog::write_raw(b" elr=");
        klog::write_hex_u64(elr);
        // For data/instruction-abort EC values, decode the ISS DFSC
        // sub-field per ARM ARM D17.2.40 / D17.2.36.
        if matches!(ec, 0x20 | 0x21 | 0x24 | 0x25) {
            klog::write_raw(b" dfsc=");
            klog::write_raw(decode_dfsc(iss as u64));
            // WnR (bit 6 of ISS) only meaningful for data aborts.
            if matches!(ec, 0x24 | 0x25) {
                klog::write_raw(if (iss & (1 << 6)) != 0 { b" W" } else { b" R" });
            }
        }
        klog::write_raw(b"\n");
    }
    #[cfg(not(feature = "debug-irq"))]
    { let _ = (esr, far, elr); }
}

/// Map an `ESR_EL1.EC` value to a short label per ARM ARM
/// D17.2.36 Tab. D17-2 (the cases we expect in v1; other classes
/// fall through to `"unknown"`).
const fn ec_label(ec: u32) -> &'static [u8] {
    match ec {
        0x00 => b"unknown",
        0x07 => b"sve/fp/simd-trap",
        0x0e => b"illegal-execution",
        0x15 => b"svc-aarch64",
        0x18 => b"msr/mrs/sys-trap",
        0x20 => b"insn-abort-lower-el",
        0x21 => b"insn-abort-same-el",
        0x22 => b"pc-alignment",
        0x24 => b"data-abort-lower-el",
        0x25 => b"data-abort-same-el",
        0x26 => b"sp-alignment",
        0x2c => b"trapped-fp64",
        0x2f => b"serror",
        0x30 => b"breakpoint-lower-el",
        0x31 => b"breakpoint-same-el",
        0x32 => b"step-lower-el",
        0x33 => b"step-same-el",
        0x34 => b"watchpoint-lower-el",
        0x35 => b"watchpoint-same-el",
        0x3c => b"brk",
        _    => b"unknown",
    }
}

/// Decode the Data/Instruction-abort `DFSC` (ESR.ISS bits 0..5)
/// per ARM ARM D17.2.40 Tab. D17-22. Only the cases we expect are
/// listed; the rest fall through to `"other"`.
const fn decode_dfsc(iss: u64) -> &'static [u8] {
    match iss & 0x3f {
        0b000000 => b"address-size-l0",
        0b000001 => b"address-size-l1",
        0b000010 => b"address-size-l2",
        0b000011 => b"address-size-l3",
        0b000100 => b"translation-l0",
        0b000101 => b"translation-l1",
        0b000110 => b"translation-l2",
        0b000111 => b"translation-l3",
        0b001001 => b"access-flag-l1",
        0b001010 => b"access-flag-l2",
        0b001011 => b"access-flag-l3",
        0b001101 => b"permission-l1",
        0b001110 => b"permission-l2",
        0b001111 => b"permission-l3",
        0b010000 => b"sync-external",
        0b010001 => b"tag-check",
        0b100001 => b"alignment",
        _        => b"other",
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_dfsc, ec_label};

    #[test]
    fn ec_label_matches_arm_arm_d17_2_36() {
        assert_eq!(ec_label(0x15), b"svc-aarch64");
        assert_eq!(ec_label(0x21), b"insn-abort-same-el");
        assert_eq!(ec_label(0x25), b"data-abort-same-el");
        assert_eq!(ec_label(0x99), b"unknown");
    }

    #[test]
    fn decode_dfsc_translation_levels() {
        assert_eq!(decode_dfsc(0b000100), b"translation-l0");
        assert_eq!(decode_dfsc(0b000111), b"translation-l3");
    }

    #[test]
    fn decode_dfsc_permission_levels() {
        assert_eq!(decode_dfsc(0b001101), b"permission-l1");
        assert_eq!(decode_dfsc(0b001111), b"permission-l3");
    }

    #[test]
    fn decode_dfsc_uses_only_low_6_bits() {
        // ISS bits above DFSC (incl. WnR) don't perturb the decode.
        assert_eq!(decode_dfsc(0xffff_ffff_ffff_ff04), decode_dfsc(0b000100));
    }
}
