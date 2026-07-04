use core::sync::atomic::AtomicPtr;

use crate::RequestId;

// ---------------------------------------------------------------------------
// SMP request / response (Limine ≥ 6, x86_64 layout)
// ---------------------------------------------------------------------------

/// SMP request flag bit 0 = "request X2APIC mode if available".
/// v1 leaves this off; xAPIC is fine for QEMU virt CPU counts.
pub const SMP_FLAG_X2APIC: u64 = 1 << 0;

/// `limine_smp_request` — the request struct's flags word follows
/// the response pointer, so we can't reuse the generic
/// `RequestHeader<R>`. Layout matches `limine-protocol/include/limine.h`
/// v12 verbatim.
#[repr(C)]
pub struct SmpRequest {
    pub id:       RequestId,
    pub revision: u64,
    pub response: AtomicPtr<SmpResponse>,
    pub flags:    u64,
}

// SAFETY: same rationale as `RequestHeader`: bootloader writes
// `response` once before the kernel touches it; afterwards the
// pointer is read-only from the kernel side.
unsafe impl Sync for SmpRequest {}

/// `limine_smp_response` (x86_64) per Limine v6+.
///
/// `cpus` points to `[*const SmpInfoX86; cpu_count]` — the same
/// indirection pattern as `MemmapResponse::entries`.
#[repr(C)]
pub struct SmpResponse {
    pub revision:     u64,
    pub flags:        u32,
    pub bsp_lapic_id: u32,
    pub cpu_count:    u64,
    pub cpus:         *const *mut SmpInfoX86,
}

/// `limine_smp_info` x86_64 layout. AP spinwaits on `goto_address`;
/// when the boot CPU stores a non-null fn pointer there, the AP
/// jumps to it with `rdi = &SmpInfoX86` and an `extra_argument`
/// the kernel chose. The fn signature is
/// `unsafe extern "C" fn(*mut SmpInfoX86) -> !`.
#[repr(C)]
pub struct SmpInfoX86 {
    pub processor_id:   u32,
    pub lapic_id:       u32,
    pub reserved:       u64,
    /// Atomic pointer the AP polls; boot CPU writes the entry fn.
    pub goto_address:   AtomicPtr<()>,
    /// Stored verbatim in `extra_argument`; passed via the
    /// per-AP context (we use it for the per-AP context pointer).
    pub extra_argument: u64,
}

// ---------------------------------------------------------------------------
// SMP request / response (aarch64 layout). Same request id + revision as
// x86; the response + info structs differ (mpidr/gic_iface_no instead of
// lapic_id). Limine starts each AP at `goto_address` in the SAME state as
// the BSP entry (EL1, MMU on, kernel page tables) with x0 = &SmpInfoArm —
// so the AP can jump straight to a higher-half VA entry (no MMU
// trampoline, unlike a bare PSCI CPU_ON which starts MMU-off).
// ---------------------------------------------------------------------------

/// `limine_smp_request` for aarch64 (identical shape to `SmpRequest`, but
/// its `response` points at the aarch64 response variant).
#[repr(C)]
pub struct SmpRequestAArch64 {
    pub id:       RequestId,
    pub revision: u64,
    pub response: AtomicPtr<SmpResponseAArch64>,
    pub flags:    u64,
}
// SAFETY: bootloader writes `response` once before the kernel reads it.
unsafe impl Sync for SmpRequestAArch64 {}

/// `limine_smp_response` (aarch64) per Limine v6+. Note the 4-byte pad
/// after `flags` before the 8-aligned `bsp_mpidr` (handled by repr(C)).
#[repr(C)]
pub struct SmpResponseAArch64 {
    pub revision:  u64,
    pub flags:     u32,
    pub bsp_mpidr: u64,
    pub cpu_count: u64,
    pub cpus:      *const *mut SmpInfoAArch64,
}

/// `limine_smp_info` (aarch64). AP spinwaits on `goto_address`; when the
/// boot CPU stores a non-null fn pointer there, the AP jumps to it with
/// `x0 = &SmpInfoAArch64`. Entry fn: `unsafe extern "C" fn(*mut SmpInfoAArch64) -> !`.
#[repr(C)]
pub struct SmpInfoAArch64 {
    pub processor_id: u32,
    pub gic_iface_no: u32,
    pub mpidr:        u64,
    pub reserved:     u64,
    pub goto_address: AtomicPtr<()>,
    pub extra_argument: u64,
}
