/// Map an Intel-SDM exception vector to a short label (Vol. 3
/// Tab. 6-1). Returns a static byte slice; unknown vectors fall
/// through to `"reserved"`.
// Consumed only by the oops printer inside `oxide_fault_print_rust`, which is
// itself gated on the kernel target plus the debug-irq / debug-watchdog emit
// gate; the host unit tests below pin the table.
#[cfg(any(test, all(target_arch = "x86_64", target_os = "oxide-kernel",
                    any(feature = "debug-irq", feature = "debug-watchdog"))))]
pub(super) const fn vector_label(vec: u64) -> &'static [u8] {
    match vec {
         0 => b"#DE",        1 => b"#DB",        2 => b"NMI",        3 => b"#BP",
         4 => b"#OF",        5 => b"#BR",        6 => b"#UD",        7 => b"#NM",
         8 => b"#DF",       10 => b"#TS",       11 => b"#NP",       12 => b"#SS",
        13 => b"#GP",       14 => b"#PF",       16 => b"#MF",       17 => b"#AC",
        18 => b"#MC",       19 => b"#XM",       20 => b"#VE",       21 => b"#CP",
        _  => b"reserved",
    }
}

/// Decode the page-fault error code (PFEC) per Intel SDM Vol. 3
/// §6.15. Returns a fixed label encoding the four bits we care
/// about: P/!P (present?), W/R (write?), U/K (user/kernel?), I
/// (instruction fetch). Sixteen possible labels statically.
// Same gate as `vector_label`: oops-printer-only, plus the host tests below.
#[cfg(any(test, all(target_arch = "x86_64", target_os = "oxide-kernel",
                    any(feature = "debug-irq", feature = "debug-watchdog"))))]
pub(super) const fn decode_pfec(err: u64) -> &'static [u8] {
    let p   = (err & (1 << 0)) != 0;     // 1 = protection violation, 0 = not present
    let w   = (err & (1 << 1)) != 0;     // 1 = write, 0 = read
    let u   = (err & (1 << 2)) != 0;     // 1 = user, 0 = kernel
    let id  = (err & (1 << 4)) != 0;     // 1 = instruction fetch
    match (p, w, u, id) {
        (false, false, false, false) => b"NP-R-K",
        (false, false, false, true ) => b"NP-R-K-IFetch",
        (false, false, true,  false) => b"NP-R-U",
        (false, false, true,  true ) => b"NP-R-U-IFetch",
        (false, true,  false, false) => b"NP-W-K",
        (false, true,  false, true ) => b"NP-W-K-IFetch",
        (false, true,  true,  false) => b"NP-W-U",
        (false, true,  true,  true ) => b"NP-W-U-IFetch",
        (true,  false, false, false) => b"PV-R-K",
        (true,  false, false, true ) => b"PV-R-K-IFetch",
        (true,  false, true,  false) => b"PV-R-U",
        (true,  false, true,  true ) => b"PV-R-U-IFetch",
        (true,  true,  false, false) => b"PV-W-K",
        (true,  true,  false, true ) => b"PV-W-K-IFetch",
        (true,  true,  true,  false) => b"PV-W-U",
        (true,  true,  true,  true ) => b"PV-W-U-IFetch",
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_pfec, vector_label};

    #[test]
    fn vector_label_matches_intel_sdm_vol3_tab_6_1() {
        assert_eq!(vector_label(0),  b"#DE");
        assert_eq!(vector_label(13), b"#GP");
        assert_eq!(vector_label(14), b"#PF");
        assert_eq!(vector_label(99), b"reserved");
    }

    #[test]
    fn decode_pfec_writes_kernel_not_present() {
        // err = 0b00010 (W=1, P=0, U=0, I=0) — kernel write to a
        // not-present page; common kalloc failure path.
        assert_eq!(decode_pfec(0b00010), b"NP-W-K");
    }

    #[test]
    fn decode_pfec_user_protection_violation_instruction_fetch() {
        // err = 0b10101 (P=1, W=0, U=1, I=1) — user instruction
        // fetch from a no-exec mapping; the W^X enforcement signal.
        assert_eq!(decode_pfec(0b10101), b"PV-R-U-IFetch");
    }

    #[test]
    fn decode_pfec_uses_only_low_5_bits() {
        // High garbage bits don't perturb the decode.
        assert_eq!(decode_pfec(0xffff_ffff_ffff_0001), decode_pfec(0b1));
    }
}
