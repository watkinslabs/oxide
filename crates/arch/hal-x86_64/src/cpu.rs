use hal::CpuOps;

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
    {
        let lo = va as u32;
        let hi = (va >> 32) as u32;
        // SAFETY: `wrmsr` is a privileged write; ECX selects
        // IA32_FS_BASE (0xC000_0100). No memory effect; only changes
        // the architectural FS_BASE register.
        unsafe {
            core::arch::asm!(
                "wrmsr",
                in("ecx") 0xC000_0100u32,
                in("eax") lo,
                in("edx") hi,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = va; }
}

/// Read IA32_FS_BASE MSR (0xC000_0100). Inverse of `set_user_fs_base`;
/// `arch_prctl(ARCH_GET_FS, &out)` plumbs through this.
/// # SAFETY: `rdmsr` is privileged at CPL=0; reads only.
/// # C: O(1)
pub unsafe fn get_user_fs_base() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let lo: u32; let hi: u32;
        // SAFETY: rdmsr is privileged; ECX selects IA32_FS_BASE; no memory effect.
        unsafe {
            core::arch::asm!(
                "rdmsr",
                in("ecx") 0xC000_0100u32,
                out("eax") lo, out("edx") hi,
                options(nomem, nostack, preserves_flags),
            );
        }
        ((hi as u64) << 32) | (lo as u64)
    }
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

    /// # SAFETY: caller asserts `base` points to a valid per-CPU
    /// area whose first word is the cpu_id.
    /// # C: O(1)
    unsafe fn set_percpu_base(base: *mut u8) {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            // SAFETY: `wrgsbase` writes the GS base register from the
            // caller-supplied pointer. Requires CR4.FSGSBASE = 1, which
            // boot enables before the first call. Kernel-only insn.
            unsafe {
                core::arch::asm!(
                    "wrgsbase {b}",
                    b = in(reg) base,
                    options(nomem, nostack, preserves_flags),
                );
            }
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        { let _ = base; }
    }
}
