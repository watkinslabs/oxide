// Privileged-control-register reads per `20§7`.
//
// These return whatever the bootloader programmed; the kernel logs
// them before any subsystem touches paging so the VMM bring-up has
// a known-good baseline to work from.

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use core::arch::asm;

/// Read CR3 — page-table base + PCID per Intel SDM Vol. 3 §4.5.
/// # SAFETY: privileged read; legal at CPL=0.
/// # C: O(1)
pub fn read_cr3() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: `mov r, cr3` is privileged but legal at CPL=0
        // with no memory effects.
        unsafe {
            asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags));
        }
        return v;
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Read CR0.
/// # C: O(1)
pub fn read_cr0() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: `mov r, cr0` is privileged but legal at CPL=0.
        unsafe {
            asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags));
        }
        return v;
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Read CR4.
/// # C: O(1)
pub fn read_cr4() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: `mov r, cr4` is privileged but legal at CPL=0.
        unsafe {
            asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags));
        }
        return v;
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Enable CR4 bits required to let user code execute SSE/SSE2
/// instructions: OSFXSR (bit 9, FXSAVE/FXRSTOR enable +
/// SSE-via-XMM legal) and OSXMMEXCPT (bit 10, allow #XF). Also
/// clears CR0.EM (bit 2 — emulate-x87) so SSE doesn't redirect
/// to #UD/#NM, and sets CR0.MP (bit 1 — task-switched FPU is
/// monitored). musl's libc startup uses `movq %rbx, %xmm0` and
/// similar SSE2 instructions; without this they raise #UD.
/// # SAFETY: privileged CR0/CR4 writes legal at CPL=0; called
/// once at boot before any user code runs.
/// # C: O(1)
pub unsafe fn enable_sse() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    // SAFETY: per fn-level contract — privileged CR0/CR4 reads/writes legal at CPL=0; called once at boot pre-userspace; no concurrent CPU modifies CR4 in v1 single-CPU UP.
    unsafe {
        let mut cr0: u64;
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        cr0 &= !(1u64 << 2); // clear EM
        cr0 |=  (1u64 << 1); // set MP
        asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags));
        let mut cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= (1u64 << 9) | (1u64 << 10);
        asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
    }
}

/// Read IA32_EFER MSR (long-mode + NX enable).
/// # C: O(1)
pub fn read_efer() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let lo: u32; let hi: u32;
        // SAFETY: `rdmsr` is privileged but legal at CPL=0; ECX
        // selects the MSR (0xC0000080 = IA32_EFER).
        unsafe {
            asm!(
                "rdmsr",
                in("ecx") 0xc000_0080u32,
                out("eax") lo,
                out("edx") hi,
                options(nomem, nostack, preserves_flags),
            );
        }
        return ((hi as u64) << 32) | (lo as u64);
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_fallback_returns_zero() {
        assert_eq!(read_cr0(), 0);
        assert_eq!(read_cr3(), 0);
        assert_eq!(read_cr4(), 0);
        assert_eq!(read_efer(), 0);
    }
}
