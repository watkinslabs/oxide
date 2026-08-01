// `CR4.TSD` — the per-task time-stamp-disable bit behind
// `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)`.
//
// With TSD set, `rdtsc`/`rdtscp` executed at CPL>0 raise `#GP(0)`; the
// user-fault path then classifies vector 13 into SIGSEGV. Kernel-mode reads
// (CPL=0) are unaffected, so the timekeeping code keeps working while a
// sandboxed thread cannot read the counter.
//
// The bit is a CPU register, not task state: whoever owns the task's TSC mode
// must re-assert it on every context switch, exactly as the FPU area is
// saved/restored there.

/// `X86_CR4_TSD` — Intel SDM Vol. 3 §2.5, CR4 bit 2 ("time stamp disable").
pub const CR4_TSD: u64 = 1 << 2;

/// Force `CR4.TSD` to `on` for the CPU this call runs on.
///
/// Read-modify-write, so a write is skipped when the bit already matches —
/// a `mov cr4` is a serialising instruction and the switch path takes it on
/// every task change otherwise.
///
/// # SAFETY: `mov cr4` is privileged and legal at CPL=0. CR4 is per-CPU, so
/// each CPU is the sole writer of its own; callers run with preemption and
/// IRQs disabled so the read-modify-write cannot be interleaved by a nested
/// switch on this CPU. No other CR4 bit is disturbed.
/// # C: O(1)
/// # Ctx: process|irq; preempt-off
pub unsafe fn set_tsd(on: bool) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    // SAFETY: per fn-level contract — privileged CR4 read/write legal at CPL=0, per-CPU register, caller is preempt-off so this RMW has no interleaving writer.
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        let want = if on { cr4 | CR4_TSD } else { cr4 & !CR4_TSD };
        if want != cr4 {
            core::arch::asm!("mov cr4, {}", in(reg) want, options(nomem, nostack, preserves_flags));
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = on; }
}

/// The CR4 value `set_tsd` would install over `cr4`. Pure, so the bit math is
/// reachable from `cargo test` on any host — the asm above is not.
/// # C: O(1)
pub fn cr4_with_tsd(cr4: u64, on: bool) -> u64 {
    if on { cr4 | CR4_TSD } else { cr4 & !CR4_TSD }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tsd_is_cr4_bit_2() {
        assert_eq!(CR4_TSD, 0x4);
    }

    #[test]
    fn set_leaves_every_other_cr4_bit_alone() {
        // OSFXSR(9) | OSXMMEXCPT(10) | OSXSAVE(18) — the bits boot programs.
        let base = (1 << 9) | (1 << 10) | (1 << 18);
        assert_eq!(cr4_with_tsd(base, true), base | CR4_TSD);
        assert_eq!(cr4_with_tsd(base | CR4_TSD, false), base);
    }

    #[test]
    fn set_is_idempotent() {
        assert_eq!(cr4_with_tsd(CR4_TSD, true), CR4_TSD);
        assert_eq!(cr4_with_tsd(0, false), 0);
    }
}
