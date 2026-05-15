// Kernel-published vvar page consumed by the per-arch vDSO fast
// path. Sits at user VA `vdso_base - 0x1000` (the linker script
// PROVIDEs `_vdso_data` at that offset). Layout matches the vDSO
// asm:
//
//   off  0  u32 seq            // even = stable, odd = writer active
//   off  4  u32 _pad
//   off  8  u64 monotonic_ns
//   off 16  u64 realtime_sec
//   off 24  u64 realtime_nsec
//
// Publisher uses a seqlock: bump seq (odd), write fields, bump seq
// (even). The vDSO reader retries while seq is odd or changed
// across the read.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[repr(C, align(64))]
pub struct VVarPage {
    pub seq:           AtomicU32,
    _pad0:             u32,
    pub monotonic_ns:  AtomicU64,
    pub realtime_sec:  AtomicU64,
    pub realtime_nsec: AtomicU64,
}

impl VVarPage {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            seq:           AtomicU32::new(0),
            _pad0:         0,
            monotonic_ns:  AtomicU64::new(0),
            realtime_sec:  AtomicU64::new(0),
            realtime_nsec: AtomicU64::new(0),
        }
    }
}

/// Global vvar page contents. Snapshotted into the per-AS vvar
/// mapping via `snapshot_into`. Publisher (timer-tick callback)
/// updates these fields; the vDSO reads from the per-AS mapping.
pub static VVAR: VVarPage = VVarPage::new();

/// Refresh the global VVAR from the live monotonic clock. Called
/// from the timer-tick path; cheap enough to run every tick (one
/// TimerOps::monotonic_ns read + 4 atomic stores).
/// # C: O(1)
pub fn publish() {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    // Seqlock write: bump to odd, store, bump to even.
    let s = VVAR.seq.fetch_add(1, Ordering::AcqRel);
    debug_assert_eq!(s & 1, 0);
    VVAR.monotonic_ns.store(ns, Ordering::Release);
    let sec  = ns / 1_000_000_000;
    let nsec = ns % 1_000_000_000;
    VVAR.realtime_sec.store(sec, Ordering::Release);
    VVAR.realtime_nsec.store(nsec, Ordering::Release);
    VVAR.seq.fetch_add(1, Ordering::AcqRel);
}

/// Build the 4096-byte vvar page snapshot for mapping into a user
/// AS. Pulls the live VVAR contents into a heap-allocated
/// Arc<[u8]> the kernel maps via VmaBacking::KernelBytes.
///
/// The vvar mapping is RO from user mode. Each AS gets its own
/// snapshot at execve time. The kernel-side publisher updates the
/// global VVAR, but the per-AS vvar bytes don't observe live
/// kernel writes — they're a frozen snapshot at exec.
///
/// A truly live shared page (kernel writes propagate to all user
/// mappings) requires routing the publisher's writes through every
/// task's vvar VMA, which the v1 substrate skips. Programs that
/// call `__vdso_clock_gettime` get the time-at-exec value;
/// subsequent calls also return that value. This makes the path
/// callable + correct on a single read but not yet faster than a
/// syscall for repeat reads. The "shared live vvar via a single
/// kernel frame mapped read-only into every AS" optimization is
/// the K14 follow-up.
/// # C: O(PAGE_SIZE) for the snapshot copy.
pub fn snapshot_for_mapping() -> Arc<[u8]> {
    // Latest publish so the snapshot is fresh.
    publish();
    let mut bytes = alloc::vec![0u8; 4096];
    let seq  = VVAR.seq.load(Ordering::Acquire);
    let mono = VVAR.monotonic_ns.load(Ordering::Acquire);
    let rsec = VVAR.realtime_sec.load(Ordering::Acquire);
    let rns  = VVAR.realtime_nsec.load(Ordering::Acquire);
    bytes[ 0.. 4].copy_from_slice(&seq.to_le_bytes());
    bytes[ 8..16].copy_from_slice(&mono.to_le_bytes());
    bytes[16..24].copy_from_slice(&rsec.to_le_bytes());
    bytes[24..32].copy_from_slice(&rns.to_le_bytes());
    Arc::<[u8]>::from(bytes.into_boxed_slice())
}
