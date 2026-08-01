use hal::CpuOps;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use crate::msr;

/// Write the 64-bit value `val` to MSR `sel`.
/// # SAFETY: `wrmsr` is privileged at CPL=0; the caller owns the meaning of
/// whichever architectural register `sel` names.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[inline]
unsafe fn wrmsr(sel: u32, val: u64) {
    // SAFETY: per fn contract — `wrmsr` is legal at CPL=0; ECX selects the
    // register, EDX:EAX carry the value; no memory effect.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") sel,
            in("eax") val as u32,
            in("edx") (val >> 32) as u32,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read the 64-bit value of MSR `sel`.
/// # SAFETY: `rdmsr` is privileged at CPL=0; reads only.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[inline]
unsafe fn rdmsr(sel: u32) -> u64 {
    let lo: u32; let hi: u32;
    // SAFETY: per fn contract — `rdmsr` is legal at CPL=0; ECX selects the
    // register; no memory effect.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") sel,
            out("eax") lo, out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Write IA32_FS_BASE MSR (0xC000_0100) — the per-thread FS-segment
/// base used by user-space TLS (`fs:0x...`). Single-CPU v1; the
/// caller (typically `sys_arch_prctl(ARCH_SET_FS, va)`) owns the
/// invariant that the value is a valid user VA.
///
/// # SAFETY: `wrmsr` is privileged at CPL=0; `va` becomes the next
/// user-mode FS_BASE on this CPU. Caller validates `va` is canonical
/// and below `USER_VA_END` if user-supplied.
/// # C: O(1)
/// # Ctx: syscall context, IRQs off (FMASK clears IF on entry)
pub unsafe fn set_user_fs_base(va: u64) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    // SAFETY: per fn contract — privileged write of the architectural FS_BASE register with a caller-validated user VA.
    unsafe { wrmsr(msr::IA32_FS_BASE, va); }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = va; }
}

/// Read IA32_FS_BASE MSR (0xC000_0100). Inverse of `set_user_fs_base`;
/// `arch_prctl(ARCH_GET_FS, &out)` plumbs through this.
/// # SAFETY: `rdmsr` is privileged at CPL=0; reads only.
/// # C: O(1)
pub unsafe fn get_user_fs_base() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    // SAFETY: per fn contract — privileged read of the architectural FS_BASE register; no memory effect.
    unsafe { rdmsr(msr::IA32_FS_BASE) }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Halt this CPU until the next IRQ. `hlt` per `20§4`. On host fallback,
/// returns immediately so hosted unit tests can exercise call sites.
/// # C: O(1)
/// # Ctx: idle path
pub fn halt() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `hlt` is a privileged instruction; in kernel mode
        // (CPL=0) it parks the core until the next IRQ — no memory
        // effects beyond architectural state.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)) };
    }
}

/// Memory barrier ordering MMIO writes per `06§2`.
/// # C: O(1)
pub fn mmio_barrier() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `mfence` is unprivileged; orders all loads + stores
        // before any subsequent loads + stores per Intel SDM 8.2.5.
        unsafe { core::arch::asm!("mfence", options(nomem, nostack, preserves_flags)) };
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// CpuOps (`20§7`)
// ---------------------------------------------------------------------------

/// `current_cpu` reads `gs:0` — the per-CPU area's first word holds
/// `cpu_id`. Boot path (kernel's `_start`) writes `GS_BASE` via
/// `set_percpu_base` after carving the area out of the BSS per-CPU
/// table. Until SMP support lands, `cpu_count` returns 1 and the
/// boot CPU writes `cpu_id = 0` so the read returns 0 even when the
/// HAL is wired up.
pub struct X86CpuOps;

impl CpuOps for X86CpuOps {
    /// x86_64 userspace detects features via the `CPUID` instruction
    /// directly (glibc/musl ignore `AT_HWCAP` here), so advertise 0.
    /// # C: O(1)
    fn cpu_hwcap() -> u64 { 0 }

    /// # C: O(1)
    fn cpu_min_sigstksz() -> u64 { crate::min_sigstksz() as u64 }

    /// # C: O(1)
    fn current_cpu() -> u32 {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            let id: u32;
            // SAFETY: `mov %gs:0, %eax` reads the 32-bit word at
            // `GS_BASE + 0`. Boot path guarantees GS_BASE is set
            // (see `set_percpu_base`) and that offset 0 of the
            // per-CPU area holds the CPU id.
            unsafe {
                core::arch::asm!(
                    "mov {id:e}, gs:[0]",
                    id = out(reg) id,
                    options(nomem, nostack, preserves_flags),
                );
            }
            id
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        { 0 }
    }

    /// v1 single-CPU; SMP enumeration lands with the APIC bring-up.
    /// # C: O(1)
    fn cpu_count() -> u32 { 1 }

    /// # C: O(1)
    fn halt() { halt(); }

    /// # C: O(1)
    fn mmio_barrier() { mmio_barrier(); }

    /// Installs the per-CPU base by `wrmsr(IA32_GS_BASE)` — deliberately NOT
    /// `wrgsbase`, which would require `CR4.FSGSBASE`. That bit also hands
    /// ring 3 `wrgsbase`, and ring 3 rewriting the base ring 0 reads for
    /// `gs:[…]` is an arbitrary kernel write plus a stack pivot on the next
    /// kernel entry. `clear_cr4_fsgsbase` keeps the bit off; this MSR write
    /// is what works without it.
    /// # SAFETY: caller asserts `base` points to a valid per-CPU
    /// area whose first word is the cpu_id.
    /// # C: O(1)
    unsafe fn set_percpu_base(base: *mut u8) {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        // SAFETY: privileged write of the architectural GS_BASE register; `base` is this CPU's own per-CPU area per fn contract.
        unsafe { wrmsr(msr::IA32_GS_BASE, base as u64); }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        { let _ = base; }
    }
}
