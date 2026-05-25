// Hardware RNG for sys_getrandom per `27`.
//
// x86_64: RDRAND (Ivy Bridge+; assumed present, faulting impossible).
//
// aarch64: RNDR is ARMv8.5 FEAT_RNG (ID_AA64ISAR0_EL1[63:60] != 0).
// Executing `MRS RNDR` on a CPU without the feature is UNDEFINED —
// kernel halt on cortex-a72 (ARMv8.0, QEMU virt default). We
// probe ID_AA64ISAR0_EL1 once at boot, latch a `feat_rng` flag,
// and only emit `MRS RNDR` when the bit is set. Otherwise (and
// always as fallback when RNDR returns NZCV.V=1) we mix the
// monotonic cycle counter (CNTVCT_EL0) with the per-boot LCG —
// shape matches Linux's `arch_get_random_seed_long()` returning
// false on non-FEAT_RNG CPUs so the soft pool is the only path.
//
// Soft mixing here is NOT cryptographically strong; it's the
// boot-time seed for libtomcrypt-style userspace PRNGs which
// then run their own ChaCha20/Fortuna DRBG.

#![cfg(target_os = "oxide-kernel")]

#[cfg(target_arch = "aarch64")]
use core::sync::atomic::{AtomicU8, Ordering};

/// F196: aarch64 FEAT_RNG presence cache. 0 = unprobed, 1 = absent,
/// 2 = present. Probed lazily on first call so boot order doesn't
/// matter.
#[cfg(target_arch = "aarch64")]
static FEAT_RNG: AtomicU8 = AtomicU8::new(0);

/// One 64-bit word of hw entropy, or `None` if the cpu's hw source
/// can't satisfy after retries. Caller falls back to `lcg_next`.
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
        if !feat_rng_probe() { return None; }
        for _ in 0..16 {
            let v: u64;
            let nzcv: u64;
            // SAFETY: MRS RNDR is non-faulting only when FEAT_RNG is implemented; feat_rng_probe gates this branch by reading ID_AA64ISAR0_EL1.RNDR; we re-read NZCV immediately after to capture the V bit per ARM ARM D17.2.135.
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

/// F196: probe `ID_AA64ISAR0_EL1.RNDR` (bits 60..63) once + cache.
/// Returns true when FEAT_RNG is implemented (RNDR/RNDRRS safe).
/// # C: O(1) after first call.
#[cfg(target_arch = "aarch64")]
#[inline]
fn feat_rng_probe() -> bool {
    match FEAT_RNG.load(Ordering::Acquire) {
        1 => false,
        2 => true,
        _ => {
            let isar0: u64;
            // SAFETY: ID_AA64ISAR0_EL1 is unprivileged-readable at EL1 with no memory effects (ARM ARM D17.2.62).
            unsafe {
                core::arch::asm!(
                    "mrs {v}, id_aa64isar0_el1",
                    v = out(reg) isar0,
                    options(nomem, nostack, preserves_flags),
                );
            }
            let present = ((isar0 >> 60) & 0xf) != 0;
            FEAT_RNG.store(if present { 2 } else { 1 }, Ordering::Release);
            present
        }
    }
}
