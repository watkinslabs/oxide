// CPU identification reads per `21§7`.
//
// `MIDR_EL1`: Main ID Register. ARM ARM D11.2.83. Bits:
//   31:24 Implementer (e.g. 'A'=0x41 = ARM)
//   23:20 Variant
//   19:16 Architecture (0xF for ≥ ARMv7)
//   15:4  PartNum
//    3:0  Revision

/// Read `MIDR_EL1`. Privileged at EL1, no memory effects.
/// # C: O(1)
pub fn midr_el1() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: `mrs MIDR_EL1` is privileged at EL1 with no
        // memory side-effects. ARM ARM D11.2.83.
        unsafe {
            core::arch::asm!(
                "mrs {v}, midr_el1",
                v = out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn midr_el1_returns_zero_on_host() {
        assert_eq!(midr_el1(), 0);
    }
}
