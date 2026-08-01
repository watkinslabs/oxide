// 158 arch_prctl — one syscall, one file (docs/53 §0). ABI shim only: every
// rule (sub-code classification, the TASK_SIZE_MAX address rule, the CPUID /
// CET / xstate / address-masking ladders) lives in the hosted-testable
// `arch_prctl_abi` module; this file parses, fetches live CPU state, calls
// one work fn per sub-code, and encodes.
#![cfg(target_os = "oxide-kernel")]

#[cfg(target_arch = "x86_64")]
use core::sync::atomic::Ordering;
#[cfg(target_arch = "x86_64")]
use syscall::SyscallArgs;
#[cfg(target_arch = "x86_64")]
use syscall::errno::Errno;
#[cfg(target_arch = "x86_64")]
use crate::arch_prctl_abi::{self, ArchOp};
#[cfg(target_arch = "x86_64")]
use crate::arch_prctl_abi::cpuid::{CpuidFaultMsr, CpuidModeChange};
#[cfg(target_arch = "x86_64")]
use crate::arch_prctl_abi::shstk::{ShstkOutcome, ShstkState};
#[cfg(target_arch = "x86_64")]
use crate::userbuf::validate_user_buf_writable;

/// `cpu_feature_enabled(X86_FEATURE_USER_SHSTK)` for this port.
///
/// FALSE, and not derived from CPUID by design: the bit means "the KERNEL
/// provides user shadow stacks", which takes shadow-stack VMAs, an
/// `MSR_IA32_PL3_SSP` per thread, restore tokens in the signal frame and
/// `MSR_IA32_U_CET` programming on every switch. None of that exists here, so
/// reporting the raw CPUID bit would make `ARCH_SHSTK_ENABLE` return 0 and
/// hand a CET-aware glibc a shadow stack no `call` ever pushes to — a
/// guaranteed #CP on the first `ret`.
#[cfg(target_arch = "x86_64")]
const USER_SHSTK_ENABLED: bool = false;

/// `cpu_feature_enabled(X86_FEATURE_LAM)` for this port.
///
/// FALSE for the same reason: LAM is a CR3 control, and this kernel programs
/// no `LAM_U48`/`LAM_U57` bits into any address space, so no tag bits survive
/// a memory access however capable the silicon is.
#[cfg(target_arch = "x86_64")]
const LAM_ENABLED: bool = false;

/// Linux `put_user(v, (unsigned long __user *)arg2)` — the only failure of an
/// `ARCH_GET_*` sub-code.
#[cfg(target_arch = "x86_64")]
fn put_user_u64(ptr: u64, v: u64) -> i64 {
    if let Err(rv) = validate_user_buf_writable(ptr, 8, 1) { return rv; }
    // SAFETY: ptr byte range validated writable above; Linux put_user accepts unaligned storage.
    unsafe { core::ptr::write_unaligned(ptr as *mut u64, v); }
    0
}

/// The xstate feature mask this kernel actually saves and restores for user
/// state, taken from the live XCR0 the FPU owner programmed.
#[cfg(target_arch = "x86_64")]
fn xcomp_mask() -> u64 {
    arch_prctl_abi::xcomp_supported(hal_x86_64::xsave_active(), hal_x86_64::xsave_xcr0())
}

/// Which CPUID-faulting mechanism the running CPU offers.
#[cfg(target_arch = "x86_64")]
fn cpuid_fault_msr() -> CpuidFaultMsr {
    match hal_x86_64::cpuid_fault_kind() {
        hal_x86_64::CPUID_FAULT_INTEL => CpuidFaultMsr::Intel,
        hal_x86_64::CPUID_FAULT_AMD => CpuidFaultMsr::Amd,
        _ => CpuidFaultMsr::None,
    }
}

/// `arch_prctl(code, arg2)` — slot 158, x86_64 only. aarch64 has no such
/// syscall: no aarch64 number translates onto 158 and the route below is
/// compiled out there, so an arm caller gets the dispatcher's ENOSYS rather
/// than a fall-through into the FS-base write.
///
/// FS base is the live `IA32_FS_BASE` MSR mirrored into the task's saved
/// `arch_ctx.fs_base`, so it survives context switch (`Context::switch`
/// saves/restores it), fork (`spawn.rs` seeds the child from the live MSR)
/// and execve (a fresh image re-runs `ARCH_SET_FS` from `__libc_setup_tls`).
/// GS base is the same story one MSR over: `IA32_KERNEL_GS_BASE` while the
/// CPU is in kernel mode, mirrored into `arch_ctx.gs_base`, promoted to the
/// live GS base by the exit-path `swapgs` and cleared by execve.
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
            // SAFETY: rdmsr IA32_FS_BASE is privileged; no memory effect.
            let base = unsafe { hal_x86_64::get_user_fs_base() };
            put_user_u64(ptr, base)
        }
        // ARCH_SET_GS / ARCH_GET_GS. The value is the thread's USER GS base.
        // Kernel mode parks it in IA32_KERNEL_GS_BASE — the register the entry
        // and exit `swapgs` exchange with the live per-CPU base — so the write
        // is immediately real for ring 3 without disturbing any `gs:[..]` the
        // kernel itself performs. Mirrors the FS pair below/above it, including
        // the arch_ctx sync that keeps a fork() landing before the next
        // context switch from copying a stale base.
        ArchOp::SetGs(val) => {
            // SAFETY: val < TASK_SIZE_MAX per `classify`, so the wrmsr operand
            // is canonical; IA32_KERNEL_GS_BASE holds the per-thread user GS base
            // while the CPU is in kernel mode.
            unsafe { hal_x86_64::set_user_gs_base(val); }
            if let Some(cur) = sched::live::current() {
                // SAFETY: current is the running task on this CPU; arch_ctx is
                // single-mutator per `13§5` and this is its own syscall path.
                unsafe {
                    let p: *mut hal_x86_64::ContextX86_64 = cur.arch_ctx_ptr();
                    (*p).gs_base = val;
                }
            }
            0
        }
        ArchOp::GetGs(ptr) => {
            // SAFETY: rdmsr IA32_KERNEL_GS_BASE is privileged; no memory effect.
            let base = unsafe { hal_x86_64::get_user_gs_base() };
            put_user_u64(ptr, base)
        }
        ArchOp::GetCpuid => {
            let nocpuid = sched::live::current()
                .map(|c| c.nocpuid.load(Ordering::Acquire)).unwrap_or(false);
            arch_prctl_abi::get_cpuid_mode(nocpuid)
        }
        ArchOp::SetCpuid(enable) => {
            let Some(cur) = sched::live::current() else { return arch_prctl_abi::cpuid::enodev() };
            let now = cur.nocpuid.load(Ordering::Acquire);
            match arch_prctl_abi::set_cpuid_mode(cpuid_fault_msr(), enable, now) {
                CpuidModeChange::Enodev => arch_prctl_abi::cpuid::enodev(),
                CpuidModeChange::AlreadySet => 0,
                CpuidModeChange::Arm { nocpuid } => {
                    // Linux flips the CPU state "synchronously with TIF_NOCPUID
                    // in the current running context": the store and the MSR
                    // write must not be separated by a reschedule, or the
                    // switch path's difference test compares against a flag
                    // that already moved and skips the write.
                    cur.nocpuid.store(nocpuid, Ordering::Release);
                    // SAFETY: running on this task's CPU inside its own
                    // syscall; the callee is a no-op unless the probe found a
                    // vendor mechanism, which `set_cpuid_mode` just confirmed.
                    unsafe { hal_x86_64::set_cpuid_faulting(nocpuid); }
                    0
                }
            }
        }
        ArchOp::Shstk { option, features } => {
            let Some(cur) = sched::live::current() else {
                return -(Errno::Einval.as_i32() as i64)
            };
            let st = ShstkState {
                features: cur.shstk_features.load(Ordering::Acquire),
                locked: cur.shstk_locked.load(Ordering::Acquire),
            };
            match arch_prctl_abi::shstk_prctl(option, features, st, USER_SHSTK_ENABLED) {
                ShstkOutcome::PutUser { ptr, val } => put_user_u64(ptr, val),
                ShstkOutcome::Store(n) => {
                    cur.shstk_features.store(n.features, Ordering::Release);
                    cur.shstk_locked.store(n.locked, Ordering::Release);
                    0
                }
                ShstkOutcome::Ret(rv) => rv,
            }
        }
        ArchOp::GetXcompSupp(ptr) => put_user_u64(ptr, xcomp_mask()),
        // Permission is the supported set minus the dynamically-enabled
        // components. Nothing has been GRANTED here and nothing can be: the
        // XCR0 this kernel programs carries no AMX bit, so `xcomp_request`
        // can never return a grant to record (the `granted` argument is
        // therefore always 0, not a dropped write). Host and guest groups
        // start from the same default, so `guest` does not change the answer.
        ArchOp::GetXcompPerm { ptr, .. } =>
            put_user_u64(ptr, arch_prctl_abi::xcomp_permitted(xcomp_mask(), 0)),
        ArchOp::ReqXcompPerm { idx, .. } => {
            let supported = xcomp_mask();
            match arch_prctl_abi::xcomp_request(idx, supported,
                                                arch_prctl_abi::xcomp_permitted(supported, 0)) {
                Ok(_) => 0,
                Err(rv) => rv,
            }
        }
        ArchOp::GetUntagMask(ptr) =>
            put_user_u64(ptr, arch_prctl_abi::lam_untag_mask(
                arch_prctl_abi::lam_max_tag_bits(LAM_ENABLED))),
        ArchOp::GetMaxTagBits(ptr) =>
            put_user_u64(ptr, arch_prctl_abi::lam_max_tag_bits(LAM_ENABLED)),
        ArchOp::EnableTaggedAddr(nr_bits) =>
            arch_prctl_abi::lam_enable_tagged_addr(LAM_ENABLED, nr_bits),
        // `set_bit(MM_CONTEXT_FORCE_TAGGED_SVA, ...)` — a permission for a
        // future `ARCH_ENABLE_TAGGED_ADDR` on an mm with a live PASID. Linux
        // returns 0 for the calling task without consulting any CPU feature.
        // Recording it would be dead state: the enable it authorises can
        // never succeed while `LAM_ENABLED` is false.
        ArchOp::ForceTaggedSva => 0,
        ArchOp::MapVdso(_) => arch_prctl_abi::map_vdso_unsupported(),
    }
}
