use crate::{ARCH_CTX_SIZE, ARCH_FPU_SIZE};
pub use crate::timer_model::PosixTimer;

use super::Task;

/// 8-byte-aligned byte buffer holding a per-arch HAL `Context`.
/// Per-arch Context types start with `rsp`/`sp` which are u64;
/// the explicit alignment keeps that field at offset 0 with
/// natural alignment regardless of the buffer placement.
#[repr(C, align(8))]
pub struct ArchCtxBuf(pub [u8; ARCH_CTX_SIZE]);

/// 64-byte-aligned raw storage for the per-arch FPU/SIMD save area. XSAVE
/// #GPs on <64B alignment (FXSAVE's 16B / NEON store-pair is a subset).
#[repr(C, align(64))]
struct FpuArea([u8; ARCH_FPU_SIZE]);

/// Per-arch FPU/SIMD save area, **heap-allocated off the `Task`** (the
/// `Task` holds only this 8-byte `Box` pointer). Mirrors how Linux keeps the
/// xstate as a dynamically-sized trailing member of `task_struct` and how
/// Redox uses an `AlignedBox` `kfx`: the area must be large enough for the
/// full XSAVE state (AVX YMM / AVX512 ZMM) AND 64-byte aligned, and embedding
/// that by value would bloat every by-value `Task` move + force a 64-aligned
/// `Task` heap slot (which intermittently corrupted neighbouring allocations).
/// The ctxsw casts `as_mut_ptr()` to the HAL's `FpuStateX86_64`/`AArch64`.
pub struct ArchFpuBuf(alloc::boxed::Box<FpuArea>);

impl ArchFpuBuf {
    /// Fresh-task FPU image. NOT all-zeros: a zeroed x86 FXSAVE area has
    /// MXCSR=0 (all SSE exceptions UNMASKED) and FCW=0, which makes the
    /// first inexact/denormal SSE op in userspace #XM → spurious SIGFPE.
    /// Seed the architectural defaults (x86: FCW=0x037f, MXCSR=0x1f80) so a
    /// first-run task the ctxsw `fxrstor`/`xrstor`s starts with a sane control
    /// word. For XSAVE, the zeroed XSTATE_BV header (bytes 512..520) makes
    /// `xrstor` init every component (YMM/ZMM=0), which is correct fresh state.
    /// # C: O(1)
    pub fn arch_default() -> Self {
        let mut b = [0u8; ARCH_FPU_SIZE];
        #[cfg(target_arch = "x86_64")]
        {
            // FXSAVE layout: FCW @0 (0x037f), MXCSR @24 (0x1f80).
            b[0] = 0x7f; b[1] = 0x03;
            b[24] = 0x80; b[25] = 0x1f;
        }
        ArchFpuBuf(alloc::boxed::Box::new(FpuArea(b)))
    }

    /// Raw pointer to the 64-aligned save area for `fxsave`/`xsave` (write)
    /// and `fxrstor`/`xrstor` (read). Mutation is sound via the enclosing
    /// `UnsafeCell<ArchFpuBuf>` in `Task` (ctxsw is the single mutator).
    /// # C: O(1)
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.0.0.as_ptr() as *mut u8
    }

    /// Const view of the save area (ptrace GETREGSET reads it). # C: O(1)
    pub fn as_ptr(&self) -> *const u8 {
        self.0.0.as_ptr()
    }

    /// Raw save-area address retained only by the provenance diagnostic.
    /// # C: O(1)
    #[cfg(feature = "debug-task-fpu-provenance")]
    pub fn debug_ptr_bits(&self) -> usize { self.0.0.as_ptr() as usize }

    /// Alignment required by every supported FP/SIMD save instruction.
    /// # C: O(1)
    #[cfg(feature = "debug-task-fpu-provenance")]
    pub const fn debug_alignment() -> usize { core::mem::align_of::<FpuArea>() }
}

// SAFETY: `arch_ctx` mutation is gated by the kernel scheduler's
// runqueue invariant (only the CPU running this task writes the
// buffer, and only via `Context::switch` which is a single
// register-dance with no preempt window). Reads are likewise
// single-CPU per active-task invariant. AtomicPtr fields are
// inherently Sync.
unsafe impl Sync for Task {}
