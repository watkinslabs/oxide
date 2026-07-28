// Hardware entropy sources, per `27`. Moved here from
// `syscalls::hwrng` so the CSPRNG and its seed material have ONE owner.
//
// x86_64: RDRAND (Ivy Bridge+; non-faulting, unprivileged).
//
// aarch64: RNDR is ARMv8.5 FEAT_RNG (ID_AA64ISAR0_EL1[63:60] != 0). Executing
// `MRS RNDR` without the feature is UNDEFINED — a kernel halt on cortex-a72
// (ARMv8.0, the QEMU virt default). Probe once, latch, and only emit the
// instruction when the bit is set. Shape matches Linux
// `arch_get_random_seed_long()` returning false on non-FEAT_RNG CPUs.
//
// Neither source is assumed present. `pool.rs` never depends on one: it also
// absorbs the cycle counter (jitter) and any bulk source a driver installs
// (`virtio-rng`), and its ChaCha20 state is what actually produces output.

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
use core::sync::atomic::{AtomicU8, Ordering};

/// aarch64 FEAT_RNG presence cache. 0 = unprobed, 1 = absent, 2 = present.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
static FEAT_RNG: AtomicU8 = AtomicU8::new(0);

/// Retry budget before a hardware source is declared unavailable for this call.
const HW_RETRIES: usize = 16;

/// One 64-bit word of hardware entropy, or `None` when the CPU has no usable
/// source. # C: amortized O(1); worst case `HW_RETRIES` retries
#[inline]
pub fn hw_random_u64() -> Option<u64> {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        for _ in 0..HW_RETRIES {
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
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        if !feat_rng_probe() { return None; }
        for _ in 0..HW_RETRIES {
            let v: u64;
            let nzcv: u64;
            // SAFETY: MRS RNDR is non-faulting only when FEAT_RNG is implemented; feat_rng_probe gates this branch by reading ID_AA64ISAR0_EL1.RNDR; NZCV is re-read immediately to capture the V bit per ARM ARM D17.2.135.
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
    #[cfg(not(target_os = "oxide-kernel"))]
    { None }
}

/// Probe `ID_AA64ISAR0_EL1.RNDR` (bits 60..63) once and cache the answer.
/// # C: O(1) after the first call
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[inline]
fn feat_rng_probe() -> bool {
    const RNDR_SHIFT: u64 = 60;
    match FEAT_RNG.load(Ordering::Relaxed) {
        1 => return false,
        2 => return true,
        _ => {}
    }
    let isar0: u64;
    // SAFETY: ID_AA64ISAR0_EL1 is an EL1-readable feature-ID register; the read is architecturally defined on every ARMv8 CPU and has no side effects.
    unsafe { core::arch::asm!("mrs {}, ID_AA64ISAR0_EL1", out(reg) isar0, options(nomem, nostack)); }
    let present = (isar0 >> RNDR_SHIFT) & 0xf != 0;
    FEAT_RNG.store(if present { 2 } else { 1 }, Ordering::Relaxed);
    present
}

/// Free-running cycle counter — the jitter source Linux folds in through
/// `add_interrupt_randomness`. Always available on both arches, so it is what
/// keeps the pool moving on a CPU with no RDRAND/RNDR. # C: O(1)
#[inline]
pub fn cycles() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let lo: u32; let hi: u32;
        // SAFETY: RDTSC is unprivileged (CR4.TSD clear on this kernel), reads no memory, and writes only the named EAX/EDX outputs.
        unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)); }
        ((hi as u64) << 32) | lo as u64
    }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: CNTVCT_EL0 is the architecturally mandated virtual counter, readable at EL1 with no side effects.
        unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack)); }
        v
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        // Hosted tests have no cycle counter; a monotonic counter keeps the
        // absorb path exercised without pretending to be an entropy source.
        use core::sync::atomic::{AtomicU64, Ordering};
        static TICK: AtomicU64 = AtomicU64::new(0);
        TICK.fetch_add(1, Ordering::Relaxed)
    }
}
