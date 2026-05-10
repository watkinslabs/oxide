// aarch64 FP/SIMD lazy save per `14§7`. Kernel built
// `-fp-armv8,-neon` (`07§3`); userspace freely uses FP/SIMD.
//
// FP/SIMD trap on access via `CPACR_EL1.FPEN` cleared. The trap
// handler reads `FPU_OWNER`, saves the prior owner's state, loads
// the current task's state, sets `FPU_OWNER`, sets `CPACR_EL1.FPEN`.
//
// v1 lands the data + asm primitives. The actual FP-disabled trap
// handler rides alongside the EL1 vector-table setup in `22§*`.

use core::sync::atomic::{AtomicPtr, Ordering};

/// FP/SIMD state size per `14§7.2`: 32 × 16 B vec + 32-bit FPCR +
/// 32-bit FPSR + padding to 16-byte alignment = 528 B.
pub const FPU_STATE_BYTES: usize = 32 * 16 + 16; // 528

/// Saved FP/SIMD state. Layout-pinned: `q[i]` at offset `i*16`,
/// `fpcr` at 0x200, `fpsr` at 0x204.
#[repr(C, align(16))]
#[derive(Copy, Clone)]
pub struct FpuStateAArch64 {
    pub q:    [[u8; 16]; 32], // q0..q31, 512 B
    pub fpcr: u32,            // FP control
    pub fpsr: u32,            // FP status
    _pad: [u8; 8],
}

impl FpuStateAArch64 {
    /// # C: O(1)
    pub const fn zeroed() -> Self {
        Self { q: [[0; 16]; 32], fpcr: 0, fpsr: 0, _pad: [0; 8] }
    }
}

impl Default for FpuStateAArch64 {
    fn default() -> Self { Self::zeroed() }
}

/// Per-CPU FP-owner pointer per `14§7`. SMP migration deferred to
/// v1.x per `14§7.1`.
pub static FPU_OWNER: AtomicPtr<FpuStateAArch64> = AtomicPtr::new(core::ptr::null_mut());

/// Save the FP/SIMD state to `state`. Walks q0..q31 with `stp` pairs
/// then stores fpcr/fpsr.
///
/// # SAFETY: `state` points to a writable, 16-byte-aligned
/// `FpuStateAArch64`-sized region; FP/SIMD is currently enabled
/// (CPACR_EL1.FPEN allows EL1 access).
/// # C: O(1) — bounded stp/mrs sequence
pub unsafe fn fpu_save(state: *mut FpuStateAArch64) {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: 16 stp-pairs + 2 mrs writes; `state` aligned per contract; FPEN allows the FP insns to issue without trapping (ARM ARM C7.2). `.arch_extension fp` re-enables q-reg insns at assembler level since kernel is built -fp-armv8 per 07§3.
        unsafe {
            core::arch::asm!(
                ".arch_extension fp",
                "stp  q0,  q1,  [{s}, #0x000]",
                "stp  q2,  q3,  [{s}, #0x020]",
                "stp  q4,  q5,  [{s}, #0x040]",
                "stp  q6,  q7,  [{s}, #0x060]",
                "stp  q8,  q9,  [{s}, #0x080]",
                "stp q10, q11,  [{s}, #0x0a0]",
                "stp q12, q13,  [{s}, #0x0c0]",
                "stp q14, q15,  [{s}, #0x0e0]",
                "stp q16, q17,  [{s}, #0x100]",
                "stp q18, q19,  [{s}, #0x120]",
                "stp q20, q21,  [{s}, #0x140]",
                "stp q22, q23,  [{s}, #0x160]",
                "stp q24, q25,  [{s}, #0x180]",
                "stp q26, q27,  [{s}, #0x1a0]",
                "stp q28, q29,  [{s}, #0x1c0]",
                "stp q30, q31,  [{s}, #0x1e0]",
                "mrs {t}, fpcr",
                "str {t:w},     [{s}, #0x200]",
                "mrs {t}, fpsr",
                "str {t:w},     [{s}, #0x204]",
                s = in(reg) state,
                t = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { let _ = state; }
}

/// Restore FP/SIMD state from `state`.
///
/// # SAFETY: `state` points to a readable, 16-byte-aligned
/// `FpuStateAArch64`; bytes were written by a prior `fpu_save` (or
/// are a zeroed initial state); FP/SIMD enabled.
/// # C: O(1)
pub unsafe fn fpu_restore(state: *const FpuStateAArch64) {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: 16 ldp-pairs + 2 msr writes; `state` valid per contract; FPEN allows FP insns to issue. `.arch_extension fp` re-enables q-reg insns at assembler level since kernel is built -fp-armv8 per 07§3.
        unsafe {
            core::arch::asm!(
                ".arch_extension fp",
                "ldp  q0,  q1,  [{s}, #0x000]",
                "ldp  q2,  q3,  [{s}, #0x020]",
                "ldp  q4,  q5,  [{s}, #0x040]",
                "ldp  q6,  q7,  [{s}, #0x060]",
                "ldp  q8,  q9,  [{s}, #0x080]",
                "ldp q10, q11,  [{s}, #0x0a0]",
                "ldp q12, q13,  [{s}, #0x0c0]",
                "ldp q14, q15,  [{s}, #0x0e0]",
                "ldp q16, q17,  [{s}, #0x100]",
                "ldp q18, q19,  [{s}, #0x120]",
                "ldp q20, q21,  [{s}, #0x140]",
                "ldp q22, q23,  [{s}, #0x160]",
                "ldp q24, q25,  [{s}, #0x180]",
                "ldp q26, q27,  [{s}, #0x1a0]",
                "ldp q28, q29,  [{s}, #0x1c0]",
                "ldp q30, q31,  [{s}, #0x1e0]",
                "ldr {t:w},     [{s}, #0x200]",
                "msr fpcr, {t}",
                "ldr {t:w},     [{s}, #0x204]",
                "msr fpsr, {t}",
                s = in(reg) state,
                t = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { let _ = state; }
}

/// Disable FP/SIMD on this CPU. Clears `CPACR_EL1.FPEN` so the
/// next FP insn traps. Per `14§7` step 1.
/// # C: O(1)
pub fn fpu_disable() {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `mrs / msr CPACR_EL1` is privileged at EL1; we
        // clear only the FPEN bits (20:21) and write back. ARM ARM
        // D13.2.31. `isb` ensures the masked state is in effect
        // before the next instruction stream.
        unsafe {
            core::arch::asm!(
                "mrs {r}, cpacr_el1",
                "bic {r}, {r}, #(0x3 << 20)",
                "msr cpacr_el1, {r}",
                "isb",
                r = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }
}

/// Enable FP/SIMD on this CPU. Sets `CPACR_EL1.FPEN` (bits 20:21 = 0b11
/// for "no trap at EL0/EL1"). Per `14§7` step 4 final action.
/// # C: O(1)
pub fn fpu_enable() {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: as above — privileged read-modify-write of
        // CPACR_EL1; sets FPEN to allow EL0/EL1 FP access.
        unsafe {
            core::arch::asm!(
                "mrs {r}, cpacr_el1",
                "orr {r}, {r}, #(0x3 << 20)",
                "msr cpacr_el1, {r}",
                "isb",
                r = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fpu_state_size_matches_spec() {
        // `14§7.2`: 32×16 vec + ctrl ⇒ 528 B with align(16) padding.
        assert_eq!(core::mem::size_of::<FpuStateAArch64>(), FPU_STATE_BYTES);
        assert_eq!(FPU_STATE_BYTES, 528);
    }

    #[test]
    fn fpu_state_alignment() {
        assert_eq!(core::mem::align_of::<FpuStateAArch64>(), 16);
    }

    #[test]
    fn fpu_state_offsets_match_asm() {
        // Asm uses literal `[s, #0xNN]` offsets. Reordering the
        // struct breaks save/restore.
        assert_eq!(core::mem::offset_of!(FpuStateAArch64, q),    0x000);
        assert_eq!(core::mem::offset_of!(FpuStateAArch64, fpcr), 0x200);
        assert_eq!(core::mem::offset_of!(FpuStateAArch64, fpsr), 0x204);
    }

    #[test]
    fn fpu_owner_starts_null() {
        let p = FPU_OWNER.load(Ordering::Acquire);
        assert!(p.is_null());
    }

    #[test]
    fn fpu_save_restore_compile_on_host() {
        let mut state = FpuStateAArch64::zeroed();
        // SAFETY: hosted test; `state` is a stack-local 16-byte
        // aligned FpuState; asm cfg'd out so no real FP insns run.
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
