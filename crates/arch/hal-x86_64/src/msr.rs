// Model-specific-register numbers and the CR4 feature bits this HAL
// programs. Hardware IDs, not policy: nothing here reads or writes a
// register — call sites in `cpu.rs`, `context.rs`, `regs.rs` and
// `syscall.rs` do. Ungated on purpose so the numbers are unit-testable
// (a wrong MSR selector is a silent `#GP` or a silent wrong-register
// write on the kernel target only).

/// `IA32_FS_BASE` — the 64-bit FS segment base in long mode.
pub const IA32_FS_BASE: u32 = 0xC000_0100;

/// `IA32_GS_BASE` — the ACTIVE GS segment base.
pub const IA32_GS_BASE: u32 = 0xC000_0101;

/// `IA32_KERNEL_GS_BASE` — the inactive GS base `swapgs` exchanges with
/// `IA32_GS_BASE`. Holds the USER GS base while the CPU is in kernel mode
/// and the kernel per-CPU base while the CPU is in user mode.
pub const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// `IA32_CR_PAT` — eight 8-bit page-attribute entries.
pub const IA32_CR_PAT: u32 = 0x0000_0277;

/// `CR4.FSGSBASE` (bit 16) — enables the unprivileged `rdfsbase`,
/// `wrfsbase`, `rdgsbase`, `wrgsbase` instructions at ALL privilege levels.
///
/// Held CLEAR by this port. Two consequences, both load-bearing:
///  * ring 3 cannot write a GS base, so the only GS bases the CPU ever sees
///    are the ones the kernel installs by `wrmsr` or exchanges by `swapgs`;
///  * therefore a negative (bit-63-set) `IA32_GS_BASE` proves the kernel
///    per-CPU base is live, which is what the paranoid exception entry
///    tests to decide whether it must `swapgs`.
/// Enabling the bit invalidates that test and would require a per-CPU base
/// lookup that does not go through GS at all.
pub const CR4_FSGSBASE: u64 = 1 << 16;

/// CR4 with the FSGSBASE bit forced off. # C: O(1)
pub const fn cr4_without_fsgsbase(cr4: u64) -> u64 { cr4 & !CR4_FSGSBASE }

/// Does `gs_base` name a kernel address (bit 63 set)?
///
/// The rule the paranoid exception entry encodes in asm: with
/// [`CR4_FSGSBASE`] clear, user GS bases are bounded by `TASK_SIZE_MAX` and
/// so always have bit 63 clear, while every kernel per-CPU area lives in the
/// upper canonical half.
/// # C: O(1)
pub const fn gs_base_is_kernel(gs_base: u64) -> bool { (gs_base as i64) < 0 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msr_selectors_are_the_architectural_numbers() {
        assert_eq!(IA32_FS_BASE, 0xC000_0100);
        assert_eq!(IA32_GS_BASE, 0xC000_0101);
        assert_eq!(IA32_KERNEL_GS_BASE, 0xC000_0102);
        // The three are consecutive; an off-by-one silently writes the wrong
        // segment base instead of faulting.
        assert_eq!(IA32_GS_BASE, IA32_FS_BASE + 1);
        assert_eq!(IA32_KERNEL_GS_BASE, IA32_GS_BASE + 1);
        assert_eq!(IA32_CR_PAT, 0x277);
    }

    #[test]
    fn cr4_fsgsbase_is_bit_sixteen_and_clears_cleanly() {
        assert_eq!(CR4_FSGSBASE, 0x1_0000);
        assert_eq!(cr4_without_fsgsbase(0x1_0000), 0);
        // Every other bit survives the mask (PAE|PGE|OSFXSR|SMEP|… stay put).
        assert_eq!(cr4_without_fsgsbase(0xFFFF_FFFF), 0xFFFF_FFFF & !0x1_0000);
        assert_eq!(cr4_without_fsgsbase(0), 0);
    }

    #[test]
    fn only_upper_half_gs_bases_read_as_kernel() {
        // Kernel-image per-CPU page (BSS) and an HHDM-mapped AP per-CPU page.
        assert!(gs_base_is_kernel(0xffff_ffff_8100_0000));
        assert!(gs_base_is_kernel(0xffff_8000_0010_0000));
        assert!(gs_base_is_kernel(u64::MAX));
        // Every base a user thread can install: 0 ..< TASK_SIZE_MAX.
        assert!(!gs_base_is_kernel(0));
        assert!(!gs_base_is_kernel(0x7fff_ffff_f000));
        assert!(!gs_base_is_kernel((1u64 << 47) - 4096));
        // The boundary itself: bit 63 is the whole test.
        assert!(!gs_base_is_kernel(0x7fff_ffff_ffff_ffff));
        assert!(gs_base_is_kernel(0x8000_0000_0000_0000));
    }
}
