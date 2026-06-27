// Privileged-control-register reads per `20§7`.
//
// These return whatever the bootloader programmed; the kernel logs
// them before any subsystem touches paging so the VMM bring-up has
// a known-good baseline to work from.

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use core::arch::asm;

/// DIAG: arm DR0 as an 8-byte WRITE data-watchpoint at `va`. A guest user
/// (or kernel) write to those 8 bytes raises #DB (trap-type, after the store).
/// DR7: L0=1 (enable DR0), R/W0=01 (write), LEN0=10 (8 bytes). `va` must be
/// 8-aligned. # SAFETY: privileged; legal at CPL=0.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn set_data_watchpoint(va: u64) {
    // L0=1 (bit0), GE=1 (bit9, exact data-bp), reserved bit10=1, R/W0=01
    // (write, bits16-17), LEN0=10 (8 bytes, bits18-19).
    let dr7: u64 = 1 | (1u64 << 9) | (1u64 << 10) | (0b01u64 << 16) | (0b10u64 << 18);
    // SAFETY: mov to dr0/dr7 is privileged, legal at CPL=0; no memory effects.
    unsafe {
        asm!("mov dr0, {}", in(reg) va,  options(nostack, preserves_flags));
        asm!("mov dr7, {}", in(reg) dr7, options(nostack, preserves_flags));
    }
}

/// DIAG: read DR6 (debug status) and clear it (write 0). Bit 0 set ⇒ DR0 hit.
/// # SAFETY: privileged; legal at CPL=0.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn read_clear_dr6() -> u64 {
    let v: u64;
    // SAFETY: mov from/to dr6 is privileged, legal at CPL=0.
    unsafe {
        asm!("mov {}, dr6", out(reg) v, options(nostack, preserves_flags));
        asm!("mov dr6, {}", in(reg) 0u64, options(nostack, preserves_flags));
    }
    v
}

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
/// # SAFETY: privileged CR0/CR4 writes legal at CPL=0; called once
/// per CPU at boot (BSP `_start_rust` + each AP `ap_main_x86`) before
/// that CPU runs user code. CR0/CR4 are per-CPU registers.
/// # C: O(1)
pub unsafe fn enable_sse() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    // SAFETY: per fn-level contract — privileged CR0/CR4 reads/writes legal at CPL=0; called once per CPU pre-userspace; CR0/CR4 are per-CPU so each CPU is the sole writer of its own.
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
