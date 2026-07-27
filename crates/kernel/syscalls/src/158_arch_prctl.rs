// 158 arch_prctl — one syscall, one file (docs/53 §0). ABI shim only: the
// sub-code classification, the TASK_SIZE_MAX address rule and the
// CPUID-faulting rule live in the hosted-testable `arch_prctl_abi` module.
#![cfg(target_os = "oxide-kernel")]

#[cfg(target_arch = "x86_64")]
use syscall::SyscallArgs;
#[cfg(target_arch = "x86_64")]
use syscall::errno::Errno;
#[cfg(target_arch = "x86_64")]
use crate::arch_prctl_abi::{self, ArchOp};
#[cfg(target_arch = "x86_64")]
use crate::userbuf::validate_user_buf_writable;

/// Linux `X86_FEATURE_CPUID_FAULT`. Linux only ever sets it from
/// `arch/x86/kernel/cpu/intel.c:probe_cpuid_fault`, a vendor-gated
/// `rdmsr_safe(MSR_PLATFORM_INFO)`; this port runs no such probe, so the
/// feature bit is never set and `ARCH_SET_CPUID` answers ENODEV exactly as
/// Linux does on every CPU whose probe comes back negative.
#[cfg(target_arch = "x86_64")]
const CPUID_FAULT_SUPPORTED: bool = false;

/// `arch_prctl(code, arg2)` — slot 158, x86_64 only (aarch64 has no such
/// syscall: nothing in `syscall::arm_abi` maps to 158, so the aarch64
/// dispatcher answers ENOSYS for it, which is what Linux/arm64 does).
///
/// FS base is the live `IA32_FS_BASE` MSR mirrored into the task's saved
/// `arch_ctx.fs_base`, so it survives context switch (`Context::switch`
/// saves/restores it), fork (`spawn.rs` seeds the child from the live MSR)
/// and execve (a fresh image re-runs `ARCH_SET_FS` from `__libc_setup_tls`).
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub fn kernel_arch_prctl(args: &SyscallArgs) -> i64 {
    let op = match arch_prctl_abi::classify(args.a0, args.a1) {
        Ok(op) => op,
        Err(e) => return -(e.as_i32() as i64),
    };
    match op {
        ArchOp::SetFs(val) => {
            // SAFETY: val < TASK_SIZE_MAX per `classify`, so the wrmsr operand
            // is canonical; IA32_FS_BASE is the per-thread user segment base.
            unsafe { hal_x86_64::set_user_fs_base(val); }
            // B38: keep the saved arch_ctx.fs_base in sync with the live MSR.
            // Without this, a fork() that lands before the next context switch
            // reads a stale arch_ctx.fs_base (often 0) for the child's
            // inherited TLS pointer.
            if let Some(cur) = sched::live::current() {
                // SAFETY: current is the running task on this CPU; arch_ctx is
                // single-mutator per `13§5` and this is its own syscall path.
                unsafe {
                    let p: *mut hal_x86_64::ContextX86_64 = cur.arch_ctx_ptr();
                    (*p).fs_base = val;
                }
            }
            0
        }
        ArchOp::GetFs(ptr) => {
            if let Err(rv) = validate_user_buf_writable(ptr, 8, 1) { return rv; }
            // SAFETY: rdmsr IA32_FS_BASE is privileged; no memory effect.
            let base = unsafe { hal_x86_64::get_user_fs_base() };
            // SAFETY: ptr byte range validated writable; Linux put_user accepts unaligned storage.
            unsafe { core::ptr::write_unaligned(ptr as *mut u64, base); }
            0
        }
        // ARCH_SET_GS / ARCH_GET_GS. This port runs the no-swapgs model: GS
        // base is the kernel per-CPU area at all times (the syscall entry stub
        // and every percpu accessor read `gs:[..]` with no `swapgs`), so there
        // is no register left to carry a user GS base. Honouring these two
        // sub-codes requires converting every ring transition to `swapgs`,
        // which is a HAL entry-path change (docs/54), not a syscall-ABI one.
        // Storing the value and reporting it back would be a lie: user-mode
        // `gs:` would still resolve against the kernel per-CPU base. EINVAL is
        // the honest refusal — the same answer a kernel gives for a sub-code
        // it does not implement — and `arch_prctl_abi::classify` still applies
        // the EPERM address rule first, so the error ORDER matches Linux.
        ArchOp::SetGs(_) | ArchOp::GetGs(_) => -(Errno::Einval.as_i32() as i64),
        ArchOp::GetCpuid => arch_prctl_abi::get_cpuid_mode(),
        ArchOp::SetCpuid(_) => arch_prctl_abi::set_cpuid_mode(CPUID_FAULT_SUPPORTED),
        ArchOp::Shstk => arch_prctl_abi::shstk_prctl_unsupported(),
    }
}
