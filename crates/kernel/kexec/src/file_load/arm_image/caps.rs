// What the running PE can start: translation granules and byte order.
//
// The DECODE of `ID_AA64MMFR0_EL1` is ungated and hosted-tested; only the read
// of the register itself is gated, and it is three lines. Putting the field
// arithmetic behind the same gate as the `mrs` would leave the part that can
// be wrong — a shift, an inclusive bound, a field that is unsigned where its
// neighbour is signed — with no check that can ever run.

use super::header::Caps;

/// `ID_AA64MMFR0_EL1.TGran4`, bits [31:28].
pub const TGRAN4_SHIFT: u32 = 28;
/// `ID_AA64MMFR0_EL1.TGran64`, bits [27:24].
pub const TGRAN64_SHIFT: u32 = 24;
/// `ID_AA64MMFR0_EL1.TGran16`, bits [23:20].
pub const TGRAN16_SHIFT: u32 = 20;
/// `ID_AA64MMFR0_EL1.BigEnd`, bits [11:8].
pub const BIGEND_SHIFT: u32 = 8;
/// Every field above is four bits wide.
pub const FIELD_MASK: u64 = 0xf;

/// Lowest `TGran4` value that means "implemented".
///
/// The 4 KiB and 64 KiB fields spell "not implemented" as `0xf` and everything
/// below `0x8` as implemented; the 16 KiB field spells "not implemented" as
/// `0x0` and everything from `0x1` up as implemented. The inversion is real
/// and is the single most likely thing to get backwards here, so the bounds
/// are named per field rather than shared.
pub const TGRAN4_MIN: u64 = 0x0;
/// Highest `TGran4` value that means "implemented".
pub const TGRAN4_MAX: u64 = 0x7;
/// Lowest `TGran64` value that means "implemented".
pub const TGRAN64_MIN: u64 = 0x0;
/// Highest `TGran64` value that means "implemented".
pub const TGRAN64_MAX: u64 = 0x7;
/// Lowest `TGran16` value that means "implemented".
pub const TGRAN16_MIN: u64 = 0x1;
/// Highest `TGran16` value that means "implemented".
pub const TGRAN16_MAX: u64 = 0xf;
/// `BigEnd` value that means "mixed-endian supported at EL1".
pub const BIGEND_IMP: u64 = 0x1;

/// Whether THIS kernel is big-endian. Both live arm targets here are
/// little-endian; the constant exists so the comparison in `check_features`
/// reads as a comparison rather than as a hardcoded `false`.
pub const BE_KERNEL: bool = cfg!(target_endian = "big");

/// Decode the granule and byte-order capability fields.
/// # C: O(1)
pub fn decode_mmfr0(mmfr0: u64) -> Caps {
    let f = |shift: u32| (mmfr0 >> shift) & FIELD_MASK;
    Caps {
        g4: (TGRAN4_MIN..=TGRAN4_MAX).contains(&f(TGRAN4_SHIFT)),
        g16: (TGRAN16_MIN..=TGRAN16_MAX).contains(&f(TGRAN16_SHIFT)),
        g64: (TGRAN64_MIN..=TGRAN64_MAX).contains(&f(TGRAN64_SHIFT)),
        mixed_endian: f(BIGEND_SHIFT) == BIGEND_IMP,
        be_kernel: BE_KERNEL,
    }
}

/// The running machine's capabilities.
/// # C: O(1)
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub fn host_caps() -> Caps {
    let mmfr0: u64;
    // SAFETY: `mrs` of ID_AA64MMFR0_EL1 in `host_caps` reads an EL1-readable,
    // read-only feature identification register; no memory is touched, no
    // flags change, and the value is architecturally constant for this PE.
    unsafe {
        core::arch::asm!("mrs {v}, ID_AA64MMFR0_EL1", v = out(reg) mmfr0,
                         options(nomem, nostack, preserves_flags));
    }
    decode_mmfr0(mmfr0)
}

/// The capabilities a build with no PE to ask reports.
///
/// The 4 KiB granule only, matching this port's own page size, and no
/// mixed-endian support: the honest answer for a build that cannot read the
/// register is the narrowest one, so a hosted run never accepts an image the
/// real machine would refuse.
/// # C: O(1)
#[cfg(not(all(target_os = "oxide-kernel", target_arch = "aarch64")))]
pub fn host_caps() -> Caps {
    Caps { g4: true, g16: false, g64: false, mixed_endian: false, be_kernel: BE_KERNEL }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sixteen_kilobyte_field_is_read_the_opposite_way_round_from_its_neighbours() {
        // 0 in every field: 4K and 64K say "implemented", 16K says "not".
        let c = decode_mmfr0(0);
        assert!(c.g4 && c.g64 && !c.g16);
        // 0xf in every field: the inversion flips all three the other way.
        let c = decode_mmfr0(u64::MAX);
        assert!(!c.g4 && !c.g64 && c.g16);
    }

    #[test]
    fn each_field_is_read_at_its_own_shift_and_not_its_neighbours() {
        // Only TGran16 = 1; every other field zero.
        let c = decode_mmfr0(1u64 << TGRAN16_SHIFT);
        assert!(c.g16 && c.g4 && c.g64 && !c.mixed_endian);
        // Only TGran4 = 0xf: 4 KiB gone, the others unaffected.
        let c = decode_mmfr0(FIELD_MASK << TGRAN4_SHIFT);
        assert!(!c.g4 && c.g64 && !c.g16);
        // Only TGran64 = 0xf.
        let c = decode_mmfr0(FIELD_MASK << TGRAN64_SHIFT);
        assert!(c.g4 && !c.g64 && !c.g16);
    }

    #[test]
    fn mixed_endian_is_the_exact_value_one_and_not_merely_nonzero() {
        assert!(decode_mmfr0(BIGEND_IMP << BIGEND_SHIFT).mixed_endian);
        // A reserved encoding is not a promise; anything else must read false.
        assert!(!decode_mmfr0(2u64 << BIGEND_SHIFT).mixed_endian);
        assert!(!decode_mmfr0(0).mixed_endian);
    }

    #[test]
    fn the_hosted_build_reports_the_narrowest_honest_capability_set() {
        let c = host_caps();
        assert!(!c.be_kernel);
        assert!(c.g4);
    }
}
