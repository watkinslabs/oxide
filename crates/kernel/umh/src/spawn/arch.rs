// Per-arch user page-table root allocation, the monotonic clock the waits use,
// and the processor capability words the auxiliary vector carries. Compiler-
// gated code lives here rather than being scattered through the loader.

/// Allocate a fresh user page-table root whose kernel half is cloned from the
/// master tables. # C: O(1)
pub fn new_user_root() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: post-PMM-init allocation of a fresh root frame, zeroed and populated with the shared kernel half by the architecture allocator.
    { unsafe { hal_x86_64::mmu_ops::new_user_pml4() } }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: post-PMM-init allocation of a fresh root frame, zeroed and populated with the shared kernel half by the architecture allocator.
    { unsafe { hal_aarch64::mmu_ops::new_user_l0() } }
}

/// Monotonic nanoseconds. # C: O(1)
pub fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Hardware capability word the auxiliary vector advertises. # C: O(1)
pub fn cpu_hwcap() -> u64 {
    use hal::CpuOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86CpuOps::cpu_hwcap() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmCpuOps::cpu_hwcap() }
}

/// Second hardware capability word the auxiliary vector advertises. # C: O(1)
pub fn cpu_hwcap2() -> u64 {
    use hal::CpuOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86CpuOps::cpu_hwcap2() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmCpuOps::cpu_hwcap2() }
}

/// Minimum signal-stack size the auxiliary vector advertises. # C: O(1)
pub fn cpu_min_sigstksz() -> u64 {
    use hal::CpuOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86CpuOps::cpu_min_sigstksz() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmCpuOps::cpu_min_sigstksz() }
}
