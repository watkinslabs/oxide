// Hardware RNG primitives for sys_getrandom per `27`. RDRAND on
// x86_64; RNDR (FEAT_RNG, ARMv8.5) on aarch64. Falls back to LCG
// in `devfs::misc::lcg_next` when the instruction signals
// failure or the CPU lacks the feature.

#![cfg(target_os = "oxide-kernel")]

/// Read one 64-bit word from the CPU hardware RNG. Returns `None`
/// when the success bit indicates failure (e.g. RDRAND reseed
/// pending) after the SDM-recommended 16 retries.
/// # C: amortized O(1); worst case 16 retries.
#[inline]
pub fn hw_random_u64() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        for _ in 0..16 {
            let v: u64;
            let ok: u8;
            // SAFETY: RDRAND is non-faulting + unprivileged; reads no memory; writes only the named output regs; setc captures the carry flag the instruction publishes per Intel SDM Vol 2A RDRAND.
            unsafe {
                core::arch::asm!(
                    "rdrand {v}",
                    "setc {ok}",
                    v = out(reg) v,
                    ok = out(reg_byte) ok,
                    options(nomem, nostack),
                );
            }
            if ok != 0 { return Some(v); }
        }
        None
    }
    #[cfg(target_arch = "aarch64")]
    {
        // MRS Xt, RNDR — ARMv8.5 FEAT_RNG. RNDR sets NZCV.V=0 on
        // success, V=1 on failure. CPUs without FEAT_RNG raise
        // UNDEFINED; smoke covers QEMU virt which advertises it.
        for _ in 0..16 {
            let v: u64;
            let nzcv: u64;
            // SAFETY: MRS RNDR is non-faulting on FEAT_RNG-capable CPUs; reads no memory; we re-read NZCV immediately after to capture the V bit the RNDR completion sets per ARM ARM D17.2.135.
            unsafe {
                core::arch::asm!(
                    "mrs {v}, S3_3_C2_C4_0",
                    "mrs {nzcv}, nzcv",
                    v = out(reg) v,
                    nzcv = out(reg) nzcv,
                    options(nomem, nostack),
                );
            }
            if (nzcv & (1 << 28)) == 0 { return Some(v); }
        }
        None
    }
}
