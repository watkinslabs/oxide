use crate::{ARCH_CTX_SIZE, ARCH_FPU_SIZE};

use super::Task;

/// POSIX `timer_create` slot per Linux `timer_create(2)`.
#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct PosixTimer {
    /// Absolute monotonic-ns deadline. `0` means disarmed (or empty
    /// when `signo == 0`).
    pub deadline_ns: u64,
    /// Repeat interval. `0` = one-shot.
    pub interval_ns: u64,
    /// `sigev_value` from sigevent (passed into siginfo on fire).
    pub sigev_value: u64,
    /// Linux-side signal number (1..=64). `0` ⇒ slot is FREE.
    /// `signo != 0` + `deadline_ns == 0` ⇒ allocated but disarmed.
    pub signo: i32,
    /// Number of expirations missed since the last `timer_getoverrun`.
    pub overrun: u32,
    /// Clock id used at create time (CLOCK_REALTIME / CLOCK_MONOTONIC).
    pub clockid: u32,
    /// Padding to 8-byte alignment.
    pub _pad: u32,
}

impl PosixTimer {
    pub const SLOTS: usize = 8;
}

/// 8-byte-aligned byte buffer holding a per-arch HAL `Context`.
/// Per-arch Context types start with `rsp`/`sp` which are u64;
/// the explicit alignment keeps that field at offset 0 with
/// natural alignment regardless of the buffer placement.
#[repr(C, align(8))]
pub struct ArchCtxBuf(pub [u8; ARCH_CTX_SIZE]);

/// Opaque per-arch FPU/SIMD state buffer; per-arch crate casts to
/// FpuStateX86_64 / FpuStateAArch64. align(16) per FXSAVE / NEON
/// store-pair requirements.
#[repr(C, align(16))]
pub struct ArchFpuBuf(pub [u8; ARCH_FPU_SIZE]);

impl ArchFpuBuf {
    /// Fresh-task FPU image. NOT all-zeros: a zeroed x86 FXSAVE area has
    /// MXCSR=0 (all SSE exceptions UNMASKED) and FCW=0, which makes the
    /// first inexact/denormal SSE op in userspace #XM → spurious SIGFPE.
    /// Seed the architectural defaults (x86: FCW=0x037f, MXCSR=0x1f80) so a
    /// first-run task the ctxsw `fxrstor`s starts with a sane control word.
    /// # C: O(1)
    pub fn arch_default() -> Self {
        let mut b = [0u8; ARCH_FPU_SIZE];
        #[cfg(target_arch = "x86_64")]
        {
            // FXSAVE layout: FCW @0 (0x037f), MXCSR @24 (0x1f80).
            b[0] = 0x7f; b[1] = 0x03;
            b[24] = 0x80; b[25] = 0x1f;
        }
        ArchFpuBuf(b)
    }
}

// SAFETY: `arch_ctx` mutation is gated by the kernel scheduler's
// runqueue invariant (only the CPU running this task writes the
// buffer, and only via `Context::switch` which is a single
// register-dance with no preempt window). Reads are likewise
// single-CPU per active-task invariant. AtomicPtr fields are
// inherently Sync.
unsafe impl Sync for Task {}
