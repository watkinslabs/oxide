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

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use crate::cpuid::{cpuid, cpuid_count};

/// FXSAVE area size per Intel SDM Vol. 1 Tab. 10-2.
pub const FPU_STATE_BYTES: usize = 512;

/// Hard cap on the XSAVE area this HAL will use — the full x87+SSE+AVX+
/// AVX512 state (512 legacy + 64 header + 256 AVX + 64 opmask + 512
/// ZMM_Hi256 + 1024 Hi16_ZMM ≈ 2432); 4096 leaves headroom. The per-task
/// `ArchFpuBuf` area (`sched::ARCH_FPU_SIZE`) is heap-allocated 64-aligned
/// and MUST be ≥ this — so, unlike an inline-in-`Task` buffer, enabling the
/// full state costs only heap, never a by-value `Task` bloat. Linux/Redox
/// both keep the xstate off the task struct for exactly this reason.
// Bounds the XSAVE area inside `xstate_init`, which is kernel-target-only.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub const XSAVE_MAX_BYTES: usize = 4096;

/// XCR0 components the kernel context-switches, intersected with CPU-
/// supported (CPUID.0Dh:EAX): x87(0)|SSE(1)|AVX(2)|opmask(5)|ZMM_Hi256(6)|
/// Hi16_ZMM(7)|PKRU(9). We save the FULL user state the CPU offers so glibc's AVX/AVX512
/// IFUNC paths — which it selects via `xgetbv(XCR0)` — are all correct
/// across a mid-SIMD-loop preemption (the Linux way).
// Masked against CPUID.0Dh:EAX inside `xstate_init`, which is kernel-target-only.
#[cfg(any(all(target_arch = "x86_64", target_os = "oxide-kernel"), test))]
const XCR0_WANT: u64 = 0b10_1110_0111;

/// PKRU state layout. Its feature bit and standard-format ABI live in the
/// xstate signal module; CPUID supplies the component's offset.
use crate::signal::xstate::XFEATURE_PKRU;
const PKRU_STATE_BYTES: usize = core::mem::size_of::<u32>();

/// True once `xstate_init` enabled XSAVE on the boot CPU (CR4.OSXSAVE +
/// XCR0). Read by `fpu_save`/`fpu_restore` to pick XSAVE vs the FXSAVE
/// fallback. Set identically on every CPU, so a single global is correct.
static XSAVE_ENABLED: AtomicBool = AtomicBool::new(false);
/// Exact XCR0 component bitmap installed by [`xstate_init`]. XSAVE/XRSTOR's
/// requested-feature bitmap must be a subset of this CPU-local architectural
/// state, or XRSTOR raises #GP.
static XSAVE_XCR0: AtomicU64 = AtomicU64::new(0);
/// XSAVE area size (bytes) for the enabled XCR0 (CPUID.0Dh:EBX); 0 pre-init.
static XSAVE_AREA_BYTES: AtomicUsize = AtomicUsize::new(0);
/// CPUID.0Dh:9 EBX, or zero when PKRU is not in the active XSAVE image.
/// Extended-state components begin after the 576-byte legacy/header region,
/// so zero is not a valid PKRU offset.
static PKRU_XSAVE_OFF: AtomicUsize = AtomicUsize::new(0);
/// Linux `mxcsr_feature_mask`: the MXCSR bits
/// this CPU implements, taken from an FXSAVE image's `mxcsr_mask` word.
/// `rt_sigreturn` rejects a user MXCSR with any bit outside it, because
/// `fxrstor`/`xrstor64` #GP on a reserved MXCSR bit and that #GP would land
/// in the kernel with no handler.
static MXCSR_FEATURE_MASK: AtomicU32 = AtomicU32::new(u32::MAX);

/// Exact XCR0 the ctxsw saves/restores; 0 on the FXSAVE fallback. The signal
/// frame reports it as `_fpx_sw_bytes.xfeatures` and clamps any user-supplied
/// XSTATE_BV to it. # C: O(1)
pub fn xsave_xcr0() -> u64 { XSAVE_XCR0.load(Ordering::Acquire) }

/// Linux `mxcsr_feature_mask`. # C: O(1)
pub fn mxcsr_feature_mask() -> u32 { MXCSR_FEATURE_MASK.load(Ordering::Acquire) }

/// Linux `fpu__init_system_mxcsr()`: FXSAVE a scratch area and take its
/// `mxcsr_mask` word; hardware that reports 0 means the original P6 mask.
/// Called once per CPU from `xstate_init`, before any signal can be
/// delivered. Idempotent — every CPU computes the same value.
/// # SAFETY: `fxsave` writes 512 B into a 64-byte-aligned stack local this
/// function exclusively owns; FXSR is a baseline x86_64 feature so the insn
/// cannot #UD, and CR0.TS is clear on the boot/AP path that calls this.
/// # C: O(1)
pub unsafe fn mxcsr_mask_init() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let mut fx = FpuStateX86_64::zeroed();
        // SAFETY: `fxsave` writes exactly 512 B at a 64-byte-aligned local of that size; no other reference to `fx` exists.
        unsafe { core::arch::asm!("fxsave [{s}]", s = in(reg) &mut fx as *mut FpuStateX86_64, options(nostack, preserves_flags)); }
        let mut w = [0u8; 4];
        // Offset owned by the xstate ABI table, not restated here.
        use crate::signal::xstate::MXCSR_MASK_OFF;
        w.copy_from_slice(&fx.bytes[MXCSR_MASK_OFF..MXCSR_MASK_OFF + 4]);
        let mask = u32::from_le_bytes(w);
        let mask = if mask == 0 { crate::signal::xstate::MXCSR_DEFAULT_FEATURE_MASK } else { mask };
        MXCSR_FEATURE_MASK.store(mask, Ordering::Release);
    }
}

/// True if the CPU advertises `xsave` AND it fits our buffer — i.e. the
/// ctxsw preserves the full AVX/AVX512 state. Diagnostics / callers that
/// want to log the active save mode.
/// # C: O(1)
pub fn xsave_active() -> bool { XSAVE_ENABLED.load(Ordering::Acquire) }
/// Active XSAVE area size (0 when on the FXSAVE fallback). # C: O(1)
pub fn xsave_area_bytes() -> usize { XSAVE_AREA_BYTES.load(Ordering::Acquire) }

/// Put the restrictive initial PKRU value in an otherwise fresh standard
/// XSAVE image. `XRSTOR` treats a clear PKRU XSTATE_BV bit as architectural
/// zero, which would make every future key accessible, so PKRU must be an
/// explicit component of a fresh task's image.
/// # C: O(1)
pub fn seed_initial_pkru(img: &mut [u8]) {
    if !xsave_active() { return; }
    let off = PKRU_XSAVE_OFF.load(Ordering::Acquire);
    if off == 0 { return; }
    let _ = seed_pkru_component(img, off, crate::pkru_init_value());
}

/// Write a PKRU component into a standard-format XSAVE image. Kept pure so
/// the bounds and XSTATE_BV contract are host-tested without privileged CPU
/// setup. # C: O(1)
fn seed_pkru_component(img: &mut [u8], off: usize, pkru: u32) -> bool {
    use crate::signal::xstate::{MIN_XSTATE_SIZE, XFEATURES_OFF};
    let Some(end) = off.checked_add(PKRU_STATE_BYTES) else { return false };
    if off < MIN_XSTATE_SIZE || end > img.len() || img.len() < MIN_XSTATE_SIZE { return false; }
    img[off..end].copy_from_slice(&pkru.to_le_bytes());
    let mut bv = [0u8; 8];
    bv.copy_from_slice(&img[XFEATURES_OFF..XFEATURES_OFF + 8]);
    let bv = u64::from_le_bytes(bv) | XFEATURE_PKRU;
    img[XFEATURES_OFF..XFEATURES_OFF + 8].copy_from_slice(&bv.to_le_bytes());
    true
}

/// Enable full extended-state (AVX/AVX512) context-switching on THIS CPU.
/// Called once per CPU at boot from `enable_sse` (BSP + each AP), AFTER
/// CR4.OSFXSR. Sets CR4.OSXSAVE then `xsetbv` XCR0 to the CPU-supported
/// components the kernel saves. Without this, `fpu_save`/`fpu_restore`
/// use FXSAVE (x87+SSE only) and drop YMM/ZMM across a switch — which
/// silently corrupts glibc's AVX `memcpy`/`memcmp`/`strcmp` when a
/// preemption lands mid-SIMD-loop (systemd-hwdb trie-dedup bloat +
/// intermittent desktop SIGSEGVs). glibc gates AVX on OSXSAVE+`xgetbv`,
/// so enabling XCR0 here is also what makes glibc's fast paths legal.
///
/// # SAFETY: privileged CR4/XSETBV writes, legal at CPL=0; called once
/// per CPU pre-userspace; CR4/XCR0 are per-CPU so each CPU is sole writer.
/// # C: O(1)
pub unsafe fn xstate_init() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // CPUID.01h:ECX bit 26 = XSAVE. Absent ⇒ keep the FXSAVE path.
        // SAFETY: cpuid is unprivileged, no memory effects.
        let (_, _, ecx1, _) = unsafe { cpuid(1) };
        if ecx1 & (1 << 26) == 0 { return; }
        let prev_cr4: u64;
        // SAFETY: set CR4.OSXSAVE (bit 18) so XGETBV/XSETBV/XSAVE are legal;
        // read-modify-write touches no other CR4 bit; per-CPU register.
        unsafe {
            let mut cr4: u64;
            core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
            prev_cr4 = cr4;
            cr4 |= 1u64 << 18;
            core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
        }
        // Supported XCR0 low bits: CPUID.(EAX=0Dh,ECX=0):EAX. Mask to the
        // components we save; x87|SSE are mandatory (XSETBV #GPs without them).
        // SAFETY: cpuid unprivileged, no memory effects.
        let (eax0d, _, _, _) = unsafe { cpuid_count(0x0d, 0) };
        let mut xcr0: u64 = ((eax0d as u64) & XCR0_WANT) | 0b11;
        let mut pkru_off = 0usize;
        if xcr0 & XFEATURE_PKRU != 0 {
            // CPUID.0Dh:9 describes the standard-format PKRU component.
            // Do not advertise it in XCR0 unless the image can carry it.
            // SAFETY: cpuid is unprivileged, no memory effects.
            let (size, off, _, _) = unsafe { cpuid_count(0x0d, 9) };
            let end = (off as usize).checked_add(size as usize);
            if size < PKRU_STATE_BYTES as u32 || end.is_none_or(|v| v > XSAVE_MAX_BYTES) {
                xcr0 &= !XFEATURE_PKRU;
            } else {
                pkru_off = off as usize;
            }
        }
        // SAFETY: XSETBV(ECX=0) loads XCR0 from EDX:EAX; xcr0 includes x87|SSE
        // and only CPU-supported bits, so no #GP; OSXSAVE set just above.
        unsafe {
            core::arch::asm!(
                "xsetbv",
                in("ecx") 0u32,
                in("eax") (xcr0 as u32),
                in("edx") ((xcr0 >> 32) as u32),
                options(nostack, preserves_flags),
            );
        }
        // With XCR0 now set, CPUID.0Dh:EBX = area size for the enabled set.
        // SAFETY: cpuid unprivileged, no memory effects.
        let (_, ebx0d, _, _) = unsafe { cpuid_count(0x0d, 0) };
        let area = ebx0d as usize;
        // Only arm the XSAVE path if the area fits the per-task backing.
        if area == 0 || area > XSAVE_MAX_BYTES { return; }
        XSAVE_AREA_BYTES.store(area, Ordering::Release);
        XSAVE_XCR0.store(xcr0, Ordering::Release);
        PKRU_XSAVE_OFF.store(pkru_off, Ordering::Release);
        XSAVE_ENABLED.store(true, Ordering::Release);
        // One-time boot confirmation (BSP fires first). Names the pre-existing
        // OSXSAVE (what the bootloader left → whether glibc was already using AVX),
        // the CPU's supported XCR0 set, the XCR0 we programmed, and the area size.
        static LOGGED: AtomicBool = AtomicBool::new(false);
        if !LOGGED.swap(true, Ordering::AcqRel) {
            klog::write_raw(b"[XSTATE] xsave=on pre_osxsave=");
            klog::write_dec_u64(((prev_cr4 >> 18) & 1) as u64);
            klog::write_raw(b" cpuid0d_eax="); klog::write_hex_u64(eax0d as u64);
            klog::write_raw(b" xcr0="); klog::write_hex_u64(xcr0);
            klog::write_raw(b" area="); klog::write_dec_u64(area as u64);
            klog::write_raw(b"\n");
        }
    }
}

/// Saved FPU state, viewed as the 512 B FXSAVE legacy region. 64-byte
/// aligned per XSAVE requirement (Intel SDM `XSAVE` #GPs on <64 B align;
/// FXSAVE's 16 B is a subset). The ctxsw hands `fpu_save`/`fpu_restore`
/// a pointer into the larger per-task `ArchFpuBuf` (≥ `XSAVE_MAX_BYTES`),
/// so the XSAVE path writes the full AVX/AVX512 area through this pointer;
/// this struct only names the legacy header for `arch_default` seeding.
#[repr(C, align(64))]
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
        if XSAVE_ENABLED.load(Ordering::Acquire) {
            let xcr0 = XSAVE_XCR0.load(Ordering::Acquire);
            // RFBM is the exact enabled XCR0 component set, so x87/SSE/AVX/
            // AVX512 are saved without requesting disabled components.
            // SAFETY: `xsave64` writes ≤ XSAVE_AREA_BYTES (≤ the per-task
            // backing this pointer indexes) at the caller-asserted 64-byte
            // aligned, writable operand, with the FPU enabled. Intel SDM `XSAVE`.
            unsafe {
                core::arch::asm!(
                    "xsave64 [{s}]",
                    s = in(reg) state,
                    in("eax") (xcr0 as u32),
                    in("edx") ((xcr0 >> 32) as u32),
                    options(nostack, preserves_flags),
                );
            }
        } else {
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
        if XSAVE_ENABLED.load(Ordering::Acquire) {
            let xcr0 = XSAVE_XCR0.load(Ordering::Acquire);
            // A fresh task's zeroed area has XSTATE_BV=0 → every component
            // restored to its init value (x87 FCW=0x37F, MXCSR=0x1F80,
            // YMM/ZMM=0), which is the correct fresh-thread state.
            // SAFETY: `xrstor64` loads the XCR0-enabled components from the
            // caller-asserted readable 64-byte-aligned operand, whose bytes a
            // prior `fpu_save` wrote with this same RFBM. Intel SDM `XRSTOR`.
            unsafe {
                core::arch::asm!(
                    "xrstor64 [{s}]",
                    s = in(reg) state,
                    in("eax") (xcr0 as u32),
                    in("edx") ((xcr0 >> 32) as u32),
                    options(nostack, preserves_flags),
                );
            }
        } else {
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
    fn requested_xcr0_includes_the_pkru_component() {
        assert_ne!(XCR0_WANT & (1 << 9), 0);
    }

    #[test]
    fn initial_pkru_is_an_explicit_xsave_component() {
        use crate::signal::xstate::{MIN_XSTATE_SIZE, XFEATURES_OFF};
        const TEST_PKRU_OFF: usize = MIN_XSTATE_SIZE;
        const TEST_PKRU: u32 = 0xa5a5_5a5a;
        let mut img = [0u8; TEST_PKRU_OFF + PKRU_STATE_BYTES];
        assert!(seed_pkru_component(&mut img, TEST_PKRU_OFF, TEST_PKRU));
        let mut bv = [0u8; 8];
        bv.copy_from_slice(&img[XFEATURES_OFF..XFEATURES_OFF + 8]);
        assert_ne!(u64::from_le_bytes(bv) & XFEATURE_PKRU, 0);
        assert_eq!(&img[TEST_PKRU_OFF..], &TEST_PKRU.to_le_bytes());
    }

    #[test]
    fn initial_pkru_rejects_an_image_without_header_space() {
        let mut img = [0u8; 8];
        assert!(!seed_pkru_component(&mut img, 0, 0));
    }

    #[test]
    fn fpu_state_alignment_for_xsave() {
        // XSAVE requires 64-byte alignment per Intel SDM (a superset of
        // FXSAVE's 16). The struct carries `align(64)` so any allocation
        // respects it and `xsave64`/`xrstor64` don't #GP.
        assert_eq!(core::mem::align_of::<FpuStateX86_64>(), 64);
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
