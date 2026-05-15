// Kernel-published vvar page consumed by the per-arch vDSO fast
// path. One PMM frame is allocated at boot; its kernel-side HHDM
// mirror is treated as a live `VVarPage` struct the publisher
// writes through. The per-AS vDSO mapping uses
// `VmaBacking::KernelFrame { pa }` so every user mapping shares
// the same physical frame — kernel writes propagate instantly.
//
// Layout (matches vDSO asm):
//   off  0  u32 seq            // even = stable, odd = writer active
//   off  4  u32 _pad
//   off  8  u64 monotonic_ns
//   off 16  u64 realtime_sec
//   off 24  u64 realtime_nsec

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C)]
pub struct VVarPage {
    pub seq:           core::sync::atomic::AtomicU32,
    _pad0:             u32,
    pub monotonic_ns:  AtomicU64,
    pub realtime_sec:  AtomicU64,
    pub realtime_nsec: AtomicU64,
}

/// PA of the kernel-owned vvar frame, set once at boot by `init`.
static VVAR_PA: AtomicU64 = AtomicU64::new(0);

/// Allocate one PMM frame for the vvar page, zero it via the HHDM
/// mirror, return its PA via `pa()`. Idempotent: subsequent calls
/// re-zero but don't re-allocate.
/// # SAFETY: caller is the boot path; PMM up; single-CPU pre-init.
/// # C: O(PAGE_SIZE) for the zero.
pub unsafe fn init() {
    if VVAR_PA.load(Ordering::Acquire) != 0 { return; }
    let pa = match pmm::setup::alloc_one_frame() { Some(p) => p, None => return };
    // SAFETY: HHDM offset published by mm-pmm at boot; pa was just allocated and is exclusively ours; 4096 bytes is one full PMM frame.
    unsafe {
        let va = pmm::user_as::hhdm_offset() + pa;
        core::ptr::write_bytes(va as *mut u8, 0, 4096);
    }
    VVAR_PA.store(pa, Ordering::Release);
}

/// PA of the vvar frame (0 if `init` hasn't run yet).
/// # C: O(1)
pub fn pa() -> u64 { VVAR_PA.load(Ordering::Acquire) }

/// Pointer to the live VVarPage via the HHDM mirror. None if
/// vvar hasn't been initialised.
fn live() -> Option<&'static VVarPage> {
    let pa = VVAR_PA.load(Ordering::Acquire);
    if pa == 0 { return None; }
    let va = pmm::user_as::hhdm_offset() + pa;
    // SAFETY: kernel-owned PMM frame with a published HHDM mirror; the VVarPage layout fits within 32 B at offset 0.
    Some(unsafe { &*(va as *const VVarPage) })
}

/// Refresh vvar from the live monotonic clock. Seqlock write:
/// bump seq (odd) → store fields → bump seq (even). Cheap enough
/// to run every timer tick or every syscall return.
/// # C: O(1)
pub fn publish() {
    use hal::TimerOps;
    let v = match live() { Some(v) => v, None => return };
    #[cfg(target_arch = "x86_64")]
    let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let s = v.seq.fetch_add(1, Ordering::AcqRel);
    debug_assert_eq!(s & 1, 0);
    v.monotonic_ns.store(ns, Ordering::Release);
    let sec  = ns / 1_000_000_000;
    let nsec = ns % 1_000_000_000;
    v.realtime_sec.store(sec, Ordering::Release);
    v.realtime_nsec.store(nsec, Ordering::Release);
    v.seq.fetch_add(1, Ordering::AcqRel);
}
