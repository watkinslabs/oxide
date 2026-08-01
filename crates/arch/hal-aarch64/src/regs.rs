// Privileged system-register reads per `21§7`.
//
// Same intent as `hal-x86_64::regs`: log Limine's MMU/paging
// programming before subsystem code touches it.

/// Read TTBR1_EL1 — kernel-half page-table base + ASID/CnP.
/// # C: O(1)
pub fn read_ttbr1_el1() -> u64 {
    arch_read("ttbr1_el1")
}

/// Read TTBR0_EL1 — user-half page-table base.
/// # C: O(1)
pub fn read_ttbr0_el1() -> u64 {
    arch_read("ttbr0_el1")
}

/// Read TCR_EL1 — translation control (page size, VA bits, etc.).
/// # C: O(1)
pub fn read_tcr_el1() -> u64 {
    arch_read("tcr_el1")
}

/// Read MAIR_EL1 — memory-attribute index register.
/// # C: O(1)
pub fn read_mair_el1() -> u64 {
    arch_read("mair_el1")
}

/// Read SCTLR_EL1 — system control (MMU/cache enables, etc.).
/// # C: O(1)
pub fn read_sctlr_el1() -> u64 {
    arch_read("sctlr_el1")
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
fn arch_read(reg: &'static str) -> u64 {
    // We can't take a runtime string into asm!. Branch on the
    // expected names; the compiler folds to a single `mrs`.
    match reg {
        "ttbr1_el1" => mrs_ttbr1_el1(),
        "ttbr0_el1" => mrs_ttbr0_el1(),
        "tcr_el1"   => mrs_tcr_el1(),
        "mair_el1"  => mrs_mair_el1(),
        "sctlr_el1" => mrs_sctlr_el1(),
        _ => 0,
    }
}

#[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
fn arch_read(_: &'static str) -> u64 { 0 }

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
macro_rules! mrs {
    ($name:ident, $reg:literal) => {
        fn $name() -> u64 {
            let v: u64;
            // SAFETY: `mrs <reg>` reads a privileged system register at EL1; no memory effect, no flag changes.
            unsafe {
                core::arch::asm!(
                    concat!("mrs {v}, ", $reg),
                    v = out(reg) v,
                    options(nomem, nostack, preserves_flags),
                );
            }
            v
        }
    };
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mrs!(mrs_ttbr1_el1, "ttbr1_el1");
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mrs!(mrs_ttbr0_el1, "ttbr0_el1");
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mrs!(mrs_tcr_el1,   "tcr_el1");
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mrs!(mrs_mair_el1,  "mair_el1");
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mrs!(mrs_sctlr_el1, "sctlr_el1");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_fallback_returns_zero() {
        assert_eq!(read_ttbr1_el1(), 0);
        assert_eq!(read_tcr_el1(), 0);
        assert_eq!(read_mair_el1(), 0);
        assert_eq!(read_sctlr_el1(), 0);
    }
}

// TCR_EL1 — the kernel's translation-control value. Programmed identically by
// the BSP boot path and by every AP's trampoline; named here so the two cannot
// drift, and so the field breakdown lives in one place.

/// `TCR_EL1.T0SZ`/`T1SZ` = 16 (48-bit VAs), 4 KiB granule for both regimes,
/// inner-shareable write-back/write-allocate, `IPS` = 48-bit.
pub const TCR_EL1_BASE: u64 = 0x0000_0005_B510_3510;

/// `TCR_EL1.TBI0` (bit 37) — top-byte-ignore for `TTBR0` (userspace).
///
/// Set unconditionally, exactly as Linux does. It is what makes the
/// tagged-address ABI (`prctl(PR_SET_TAGGED_ADDR_CTRL)`) hardware-real: bits
/// 63:56 of an EL0 address stop taking part in translation, so a pointer
/// carrying a tag resolves to the same page as the untagged one. Without it
/// the kernel could record the per-task flag and still fault on the first
/// tagged dereference — a flag that lies.
///
/// It is not conditional on the flag: `TBI0` is a property of the translation
/// regime, and toggling it per task would change how EVERY address in that
/// regime translates mid-flight. Linux keeps it always-on for the same reason
/// and gates only the KERNEL's willingness to accept tagged pointers.
pub const TCR_EL1_TBI0: u64 = 1 << 37;

/// The value both bring-up paths install.
pub const TCR_EL1_KERNEL: u64 = TCR_EL1_BASE | TCR_EL1_TBI0;

#[cfg(test)]
mod tcr_tests {
    use super::*;

    /// The boot asm builds this with `movz`+`movk` immediates it cannot import
    /// from Rust, so the three 16-bit lanes are pinned here. A change to
    /// `TCR_EL1_KERNEL` that is not mirrored into the asm fails this.
    #[test]
    fn kernel_tcr_lane_immediates() {
        assert_eq!(TCR_EL1_KERNEL & 0xffff, 0x3510);
        assert_eq!((TCR_EL1_KERNEL >> 16) & 0xffff, 0xB510);
        assert_eq!((TCR_EL1_KERNEL >> 32) & 0xffff, 0x0025);
        assert_eq!(TCR_EL1_KERNEL >> 48, 0);
    }

    #[test]
    fn tbi0_is_bit_37_and_tbi1_stays_clear() {
        assert_eq!(TCR_EL1_TBI0, 1 << 37);
        // TBI1 (bit 38) is for TTBR1 — the KERNEL half. Enabling it would make
        // the hardware ignore the top byte of kernel addresses, which is only
        // wanted with software tag-based sanitisers.
        assert_eq!(TCR_EL1_KERNEL & (1 << 38), 0);
        assert_eq!(TCR_EL1_KERNEL & !TCR_EL1_TBI0, TCR_EL1_BASE);
    }
}
