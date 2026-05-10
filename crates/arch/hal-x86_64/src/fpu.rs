// x86_64 FPU/SIMD lazy save per `14§7`. Kernel is built `+soft-float`
// (`07§3`) so kernel code never touches FPU; userspace does. The
// fault-driven save/restore handler reads `FPU_OWNER`, saves the
// prior owner's state to its `FpuStateX86_64`, loads the current
// task's state, and updates `FPU_OWNER`.
//
// v1 lands the data + asm primitives; the actual #NM fault handler
// rides alongside the IDT setup in `22§*`. `FpuStateX86_64` is
// FXSAVE-shaped (512 B) — XSAVE / AVX expansion to ~832 B comes
// once the boot path enables CR4.OSXSAVE + queries XCR0.

use core::sync::atomic::{AtomicPtr, Ordering};

/// FXSAVE area size per Intel SDM Vol. 1 Tab. 10-2.
pub const FPU_STATE_BYTES: usize = 512;

/// Saved FPU state. 16-byte aligned per FXSAVE requirement (Intel
/// SDM `FXSAVE` description).
#[repr(C, align(16))]
#[derive(Copy, Clone)]
pub struct FpuStateX86_64 {
    pub bytes: [u8; FPU_STATE_BYTES],
}

impl FpuStateX86_64 {
    /// # C: O(1)
    pub const fn zeroed() -> Self {
        Self { bytes: [0; FPU_STATE_BYTES] }
    }
}

impl Default for FpuStateX86_64 {
    fn default() -> Self { Self::zeroed() }
}

/// Per-CPU FPU-owner pointer (`14§7` "Per-CPU FPU owner pointer").
/// Holds either null (no owner) or a `*mut FpuStateX86_64` belonging
/// to whichever task last executed FPU on this CPU. SMP migration
/// of FPU-owners is deferred to v1.x per `14§7.1`.
pub static FPU_OWNER: AtomicPtr<FpuStateX86_64> = AtomicPtr::new(core::ptr::null_mut());

/// Save the current CPU's FPU state into `state`. Called by the #NM
/// handler before loading a new task's state.
///
/// # SAFETY: `state` points to a writable, 16-byte-aligned
/// `FpuStateX86_64`-sized region; FPU is currently enabled
/// (CR0.TS clear) so FXSAVE doesn't fault.
/// # C: O(1) — single FXSAVE
pub unsafe fn fpu_save(state: *mut FpuStateX86_64) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `fxsave` writes 512 B starting at the operand
        // address; caller asserts alignment + writability + that
        // FPU isn't disabled. Intel SDM `FXSAVE`.
        unsafe {
            core::arch::asm!(
                "fxsave [{s}]",
                s = in(reg) state,
                options(nostack, preserves_flags),
            );
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = state; }
}

/// Restore the CPU's FPU state from `state`. Called by the #NM
/// handler after saving the prior owner.
///
/// # SAFETY: `state` points to a readable, 16-byte-aligned
/// `FpuStateX86_64`; the bytes were written by a prior `fpu_save`
/// (or are a zeroed initial state for a fresh task); FPU is
/// currently enabled.
/// # C: O(1) — single FXRSTOR
pub unsafe fn fpu_restore(state: *const FpuStateX86_64) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `fxrstor` reads 512 B from the operand address;
        // caller asserts alignment + readability + that FPU isn't
        // disabled. Intel SDM `FXRSTOR`.
        unsafe {
            core::arch::asm!(
                "fxrstor [{s}]",
                s = in(reg) state,
                options(nostack, preserves_flags),
            );
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = state; }
}

/// Disable FPU on this CPU. Sets CR0.TS so the next FPU insn faults
/// with #NM (Device Not Available). Per `14§7` step 1: kernel
/// entry from user disables FPU; ctxsw disables FPU; #NM handler
/// re-enables on demand.
/// # C: O(1)
pub fn fpu_disable() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: privileged but side-effect-bounded — sets CR0.TS
        // (bit 3) which causes the next FPU/SSE insn to raise #NM
        // until cleared. No memory access; no other CR0 bits are
        // touched in the read-modify-write.
        unsafe {
            core::arch::asm!(
                "mov {r}, cr0",
                "or  {r}, 8",
                "mov cr0, {r}",
                r = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }
}

/// Enable FPU on this CPU. `clts` clears CR0.TS atomically; the
/// next FPU insn won't fault. Per `14§7` step 4 final action.
/// # C: O(1)
pub fn fpu_enable() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: privileged but side-effect-bounded — `clts`
        // clears only CR0.TS. Kernel-only insn; legal at CPL=0.
        unsafe {
            core::arch::asm!("clts", options(nostack, preserves_flags));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fpu_state_size_matches_fxsave_area() {
        assert_eq!(core::mem::size_of::<FpuStateX86_64>(), FPU_STATE_BYTES);
        assert_eq!(FPU_STATE_BYTES, 512);
    }

    #[test]
    fn fpu_state_alignment_for_fxsave() {
        // FXSAVE requires 16-byte alignment per Intel SDM. The struct
        // carries `align(16)` so any allocation respects it.
        assert_eq!(core::mem::align_of::<FpuStateX86_64>(), 16);
    }

    #[test]
    fn fpu_owner_starts_null() {
        let p = FPU_OWNER.load(Ordering::Acquire);
        assert!(p.is_null());
    }

    #[test]
    fn fpu_save_restore_compile_on_host() {
        // Host fallback path is a no-op; we just verify the call
        // surface compiles + the contract type-checks.
        let mut state = FpuStateX86_64::zeroed();
        // SAFETY: hosted test; `state` is a stack-local 16-byte
        // aligned FpuState; the asm path is cfg'd out so no real
        // FXSAVE/FXRSTOR runs.
        unsafe {
            fpu_save(&mut state as *mut _);
            fpu_restore(&state as *const _);
        }
    }

    #[test]
    fn fpu_disable_enable_compile_on_host() {
        fpu_disable();
        fpu_enable();
    }
}
