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
