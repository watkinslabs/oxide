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

// DR7 bit-field constants (Intel SDM Vol. 3 §17.2.4). Named so the
// watchpoint arming below carries no bare magic hex.
/// DR7.L0 — local-enable DR0 (bit 0).
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const DR7_L0: u64 = 1 << 0;
/// DR7.L1 — local-enable DR1 (bit 2).
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const DR7_L1: u64 = 1 << 2;
/// DR7.GE — global-exact data-breakpoint match (bit 9, recommended set).
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const DR7_GE: u64 = 1 << 9;
/// DR7 bit 10 — reserved, read-as-one; software sets it.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const DR7_RESERVED_ONE: u64 = 1 << 10;
/// R/Wn field value: break on data WRITE only (not exec, not I/O, not r/w).
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const DR7_RW_WRITE: u64 = 0b01;
/// LENn field value: 8-byte watch length (requires 64-bit CPU support).
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const DR7_LEN_8: u64 = 0b10;
/// Shift to DR7.R/W0 (bits 16-17).
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const DR7_RW0_SHIFT: u32 = 16;
/// Shift to DR7.LEN0 (bits 18-19).
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const DR7_LEN0_SHIFT: u32 = 18;
/// Shift to DR7.R/W1 (bits 20-21).
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const DR7_RW1_SHIFT: u32 = 20;
/// Shift to DR7.LEN1 (bits 22-23).
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
const DR7_LEN1_SHIFT: u32 = 22;

/// DIAG (`debug-hw-watchpoint`): arm DR0+DR1 as 8-byte WRITE data
/// watchpoints covering a whole 16-byte `HoleHdr` at `base` — DR0 over
/// `[base, base+8)` (the `size` field) and DR1 over `[base+8, base+16)`
/// (the `next` field). A CPL=0 (or CPL=3) write to any of those 16 bytes
/// raises #DB (trap-type, after the store) so the kalloc corruption hunt's
/// in-kernel #DB handler can print the writer's `rip`. `base` must be
/// 8-aligned (every `HoleHdr` is, `MIN_HOLE_ALIGN == 8`). Re-arming
/// replaces whatever block was previously watched (single most-recently-
/// freed block, per the v1 diagnostic scope).
/// # SAFETY: privileged DR0/DR1/DR7 writes; legal at CPL=0; no mem effects.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn arm_hole_watchpoint(base: u64) {
    let dr7: u64 = DR7_L0 | DR7_L1 | DR7_GE | DR7_RESERVED_ONE
        | (DR7_RW_WRITE << DR7_RW0_SHIFT) | (DR7_LEN_8 << DR7_LEN0_SHIFT)
        | (DR7_RW_WRITE << DR7_RW1_SHIFT) | (DR7_LEN_8 << DR7_LEN1_SHIFT);
    // SAFETY: mov to dr0/dr1/dr7 is privileged, legal at CPL=0; no memory
    // effects. DR0/DR1 hold the watched HoleHdr word addresses; DR7 enables
    // both as 8-byte write watchpoints per the field constants above.
    unsafe {
        asm!("mov dr0, {}", in(reg) base,           options(nostack, preserves_flags));
        asm!("mov dr1, {}", in(reg) base + 8,       options(nostack, preserves_flags));
        asm!("mov dr7, {}", in(reg) dr7,            options(nostack, preserves_flags));
    }
}

/// DIAG (`debug-hw-watchpoint`): clear DR7's L0/L1 local-enable bits,
/// disarming both `arm_hole_watchpoint` watchpoints. Called when kalloc's
/// own `alloc()` legitimately reclaims the watched block — proof the write
/// that follows is expected reuse, not a stale-pointer UAF, so the
/// watchpoint should go quiet instead of flagging the new owner's normal
/// writes into memory it validly just received.
/// # SAFETY: privileged DR7 write; legal at CPL=0; no memory effects.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn disarm_hole_watchpoint() {
    // SAFETY: mov to dr7 is privileged, legal at CPL=0; no memory effects.
    // Clearing to 0 disables all four DRn local-enable bits at once.
    unsafe {
        asm!("mov dr7, {}", in(reg) 0u64, options(nostack, preserves_flags));
    }
}

/// DIAG (`debug-hw-watchpoint`): read back the DR0 and DR1 watch addresses
/// so the #DB handler can name which HoleHdr word a trap hit.
/// # SAFETY: privileged DR reads; legal at CPL=0.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn read_dr0_dr1() -> (u64, u64) {
    let (a, b): (u64, u64);
    // SAFETY: mov from dr0/dr1 is privileged, legal at CPL=0; pure reads.
    unsafe {
        asm!("mov {}, dr0", out(reg) a, options(nostack, preserves_flags));
        asm!("mov {}, dr1", out(reg) b, options(nostack, preserves_flags));
    }
    (a, b)
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
/// Also sets CR0.WP (bit 16) so CPL=0 writes honor the user-PTE
/// read-only bit: kernel writes into a COW-shared user page fault
/// into do_wp_page instead of silently mutating the shared frame.
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
        cr0 |=  (1u64 << 16); // set WP — CPL=0 honors user PTE RO so kernel writes to COW-shared user pages take #PF into do_wp_page instead of silently mutating the shared frame (Linux X86_CR0_WP)
        asm!("mov cr0, {}", in(reg) cr0, options(nomem, nostack, preserves_flags));
        let mut cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= (1u64 << 9) | (1u64 << 10);
        asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
        // Enable full extended-state (AVX/AVX512) context-switching on this
        // CPU: CR4.OSXSAVE + XCR0 so fpu_save/restore use XSAVE, not the
        // FXSAVE that drops YMM/ZMM. Must follow OSFXSR above. No-op on a
        // CPU without XSAVE (keeps the FXSAVE fallback). SAFETY: same
        // per-CPU-pre-userspace contract as this fn; CR4/XCR0 per-CPU.
        crate::fpu::xstate_init();
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
