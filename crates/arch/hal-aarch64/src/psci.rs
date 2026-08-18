// PSCI (Power State Coordination Interface) conduit per ARM DEN 0022.
//
// This file owns the CONDUIT — the `smc`/`hvc` instruction and the thin call
// wrappers around it. The ABI numbers, the status decode, the version gate and
// the `SYSTEM_SUSPEND` admission ladder live in `psci_uapi` / `psci_probe`,
// which carry no target gate so a hosted run can fail on them; this file is
// `target_arch = "aarch64"` and everything in it compiles out on a host x86
// test run.
//
// PSCI invocation: SMC #0 or HVC #0 depending on the conduit. QEMU `virt` runs
// the guest at EL1 with no EL3, so HVC. Return: status in x0.

#![cfg(target_arch = "aarch64")]

use core::sync::atomic::{AtomicU64, Ordering};

pub use crate::psci_uapi::{decode_status, psci_version, version_major, version_minor,
    CpuSuspendFormat, PsciStatus, PSCI_AFFINITY_INFO_64, PSCI_CPU_OFF, PSCI_CPU_ON_64,
    PSCI_CPU_SUSPEND_64, PSCI_FEATURES, PSCI_SYSTEM_OFF, PSCI_SYSTEM_RESET,
    PSCI_SYSTEM_SUSPEND_64, PSCI_VERSION, PSCI_VERSION_1_0};
use crate::psci_probe::{classify_support, decode_support, encode_support, SuspendSupport};
use crate::psci_conduit;

/// Issue an SMC instruction with up to 4 arguments and return x0.
///
/// # SAFETY: caller asserts the SMC conduit is configured (EDK2 /
/// firmware exposes it; v1 boot relies on this); IRQs masked
/// because secure-world entry is non-reentrant on most PSCI impls.
/// # C: O(SMC round-trip)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn smc(fn_id: u32, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    // SAFETY: SMC #0 is the standard PSCI conduit on EDK2 / QEMU
    // virt. Inputs go in x0..x3 per ARM DEN 0022D §5.1 calling
    // convention; the secure monitor returns the status code in x0.
    unsafe {
        // `smc #0` requires the `sec` arch extension to assemble;
        // many AArch64 assembler defaults reject it. Emit the
        // instruction encoding directly via `.inst` (0xd4000003)
        // — same opcode, no arch-extension dance.
        core::arch::asm!(
            ".inst 0xd4000003",
            inout("x0") fn_id as u64 => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            options(nomem, nostack, preserves_flags),
        );
    }
    ret
}

/// Hosted stub for SMC — returns NotSupported. Lets hosted tests
/// run without a real secure monitor.
/// # SAFETY: trivially safe; no asm.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub unsafe fn smc(_fn_id: u32, _a1: u64, _a2: u64, _a3: u64) -> i64 { -1 }

/// HVC #0 PSCI conduit — used when there is no EL3 (QEMU `virt` default
/// `secure=off`: guest runs at EL1, PSCI is serviced via the hypervisor
/// call). An `smc` there is UNDEFINED → EL1 sync exception, which is
/// exactly what wedged SMP=2 boot before B50 (BSP faulted on `smc #0` in
/// `cpu_on`, ESR_EL1 EC=0 "unknown").
/// # SAFETY: caller asserts the HVC conduit; x0..x3 per ARM DEN 0022D §5.1.
/// # C: O(1) — one PSCI call.
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn hvc(fn_id: u32, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    // SAFETY: `.inst 0xd4000002` = `hvc #0` (avoids the `virt` arch-extension assembler dance); x0..x3 are the PSCI args, x0 returns the status.
    unsafe {
        core::arch::asm!(
            ".inst 0xd4000002",
            inout("x0") fn_id as u64 => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            options(nomem, nostack, preserves_flags),
        );
    }
    ret
}

/// Hosted stub for HVC.
/// # SAFETY: trivially safe.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub unsafe fn hvc(_fn_id: u32, _a1: u64, _a2: u64, _a3: u64) -> i64 { -1 }

/// PSCI conduit dispatch. Firmware selects HVC or SMC once from its PSCI
/// description; a call before that selection fails closed.
/// # SAFETY: forwards to the conduit instruction; see `hvc`/`smc`.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
#[inline]
pub unsafe fn conduit_call(fn_id: u32, a1: u64, a2: u64, a3: u64) -> i64 {
    match psci_conduit::conduit() {
        // SAFETY: the boot path accepted this firmware conduit before any PSCI caller ran.
        Some(crate::smccc::Conduit::Smc) => unsafe { smc(fn_id, a1, a2, a3) },
        // SAFETY: the boot path accepted this firmware conduit before any PSCI caller ran.
        Some(crate::smccc::Conduit::Hvc) => unsafe { hvc(fn_id, a1, a2, a3) },
        None => -1,
    }
}
/// Hosted stub.
/// # SAFETY: trivially safe.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub unsafe fn conduit_call(_fn_id: u32, _a1: u64, _a2: u64, _a3: u64) -> i64 { -1 }

/// PSCI_CPU_ON_64: bring up the CPU identified by `target_mpidr`,
/// which on cold-power-on jumps to `entry_pa` with `context_id`
/// passed in x0 (see ARM DEN 0022D §5.1.4).
///
/// # SAFETY: caller is the boot path on the boot CPU; SMC conduit
/// is configured; `entry_pa` points at trampoline code that has
/// been published with the right cache/coherency state for AP
/// fetch.
/// # C: O(SMC round-trip)
pub unsafe fn cpu_on(target_mpidr: u64, entry_pa: u64, context_id: u64) -> PsciStatus {
    // SAFETY: per fn contract — PSCI_CPU_ON_64 via the platform conduit (HVC on QEMU virt; SMC faults at EL1 there).
    let raw = unsafe { conduit_call(PSCI_CPU_ON_64, target_mpidr, entry_pa, context_id) };
    decode_status(raw as i32)
}

/// Cached `SYSTEM_SUSPEND` probe result, encoded by `psci_probe`. Zero means
/// unprobed, which admits nothing.
static SUSPEND_SUPPORT: AtomicU64 = AtomicU64::new(0);
const CPU_SUSPEND_UNPROBED: u64 = 0;
const CPU_SUSPEND_UNSUPPORTED: u64 = 1;
const CPU_SUSPEND_ORIGINAL: u64 = 2;
const CPU_SUSPEND_EXTENDED: u64 = 3;
/// Cached CPU-suspend state format. Firmware's answer is boot-static, so the
/// provider probes it once before publishing any state that may call it.
static CPU_SUSPEND_FORMAT: AtomicU64 = AtomicU64::new(CPU_SUSPEND_UNPROBED);

/// `PSCI_VERSION`. Returns the raw major/minor word; 0 when no conduit answers.
/// # SAFETY: caller asserts the platform conduit is configured.
/// # C: O(one PSCI call)
pub unsafe fn version() -> u32 {
    // SAFETY: per fn contract — PSCI_VERSION takes no arguments and only reads firmware state.
    let raw = unsafe { conduit_call(PSCI_VERSION, 0, 0, 0) };
    raw as u32
}

/// `PSCI_FEATURES(fn_id)`. Returns the raw word: a non-negative feature-flags
/// value when the function exists, `NOT_SUPPORTED` when it does not.
/// # SAFETY: caller asserts the platform conduit is configured and that the
/// firmware is PSCI 1.0 or later, where this function exists.
/// # C: O(one PSCI call)
pub unsafe fn features(fn_id: u32) -> i64 {
    // SAFETY: per fn contract — PSCI_FEATURES queries firmware for a function ID and mutates no state.
    unsafe { conduit_call(PSCI_FEATURES, fn_id as u64, 0, 0) }
}

/// Probe `SYSTEM_SUSPEND` and cache the answer: version first, then the feature
/// query, because the query itself only exists from PSCI 1.0. Re-probing is
/// harmless; the answer cannot change under a running kernel.
/// # SAFETY: caller is the boot path, before `/sys/power/state` can be read;
/// asserts the platform conduit is configured.
/// # C: O(two PSCI calls)
pub unsafe fn probe_system_suspend() -> SuspendSupport {
    // SAFETY: per fn contract — both calls are read-only firmware queries on the configured conduit.
    let support = unsafe {
        let ver = version();
        let feat = if crate::psci_probe::version_has_features(ver) {
            features(PSCI_SYSTEM_SUSPEND_64) as i64
        } else { 0 };
        classify_support(ver, feat)
    };
    SUSPEND_SUPPORT.store(encode_support(support), Ordering::Release);
    support
}

/// The cached probe result. `Unprobed` until `probe_system_suspend` has run.
/// # C: O(1)
pub fn system_suspend_support() -> SuspendSupport {
    decode_support(SUSPEND_SUPPORT.load(Ordering::Acquire))
}

/// Probe `CPU_SUSPEND` and cache the power-state encoding it accepts.
/// # SAFETY: caller is the boot path and the platform PSCI conduit is usable.
/// # C: O(two PSCI calls at most)
pub unsafe fn probe_cpu_suspend() -> CpuSuspendFormat {
    // SAFETY: the version query is read-only and the feature query runs only
    // after PSCI 1.0 makes that query meaningful.
    let format = unsafe {
        let ver = version();
        let features = if version_major(ver) >= 1 { features(PSCI_CPU_SUSPEND_64) } else { 0 };
        crate::psci_uapi::cpu_suspend_format(ver, features)
    };
    let encoded = match format {
        CpuSuspendFormat::Unsupported => CPU_SUSPEND_UNSUPPORTED,
        CpuSuspendFormat::Original => CPU_SUSPEND_ORIGINAL,
        CpuSuspendFormat::Extended => CPU_SUSPEND_EXTENDED,
    };
    CPU_SUSPEND_FORMAT.store(encoded, Ordering::Release);
    format
}

/// Cached `CPU_SUSPEND` format, failing closed until the provider probed it.
/// # C: O(1)
pub fn cpu_suspend_format() -> CpuSuspendFormat {
    match CPU_SUSPEND_FORMAT.load(Ordering::Acquire) {
        CPU_SUSPEND_ORIGINAL => CpuSuspendFormat::Original,
        CPU_SUSPEND_EXTENDED => CpuSuspendFormat::Extended,
        _ => CpuSuspendFormat::Unsupported,
    }
}

/// Validate a firmware-provided `CPU_SUSPEND` parameter against the format the
/// platform advertised. # C: O(1)
pub fn cpu_suspend_state_valid(state: u32) -> bool {
    crate::psci_uapi::power_state_valid(state, cpu_suspend_format())
}
