// Kernel-side diagnostic callbacks kalloc cannot implement itself (no HAL /
// PMM / sched dependency): corruption probe, running-context word, IRQ info —
// plus the global diagnostic sequence counter every `[KALLOC]` line carries.

#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
use core::sync::atomic::{AtomicU64, Ordering};

/// Global monotonic counter (`debug-heappoison`) stamped on every `[KALLOC]`
/// diagnostic line, so a possibly-lossy or reordered serial capture can
/// still be placed in true event order. Motivated by a live boot where
/// `growth-register-failed` (which unconditionally panics right after
/// printing) appeared to be followed by MORE `[KALLOC]` output and a
/// DIFFERENT panic — impossible if these prints and the panic race is what
/// it looks like; a `seq=` stamp resolves whether that's a capture
/// ordering artifact or two logically distinct events. # C: O(1)
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
static KALLOC_SEQ: AtomicU64 = AtomicU64::new(0);

/// Next diagnostic sequence number (`debug-heappoison`/`debug-dealloc-diag`). # C: O(1)
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
pub(crate) fn next_seq() -> u64 { KALLOC_SEQ.fetch_add(1, Ordering::Relaxed) }

/// Callback signature for `set_corruption_probe_hook`: takes the byte
/// address of a free-list node `validate`/`try_merge` found corrupted.
/// This crate has no PMM/page-metadata dependency (it would be circular —
/// PMM's own heap growth depends on kalloc), so the actual inspection (is
/// this address's physical frame currently mapped writable somewhere it
/// shouldn't be — the "double-mapped frame, wild cross-write" hypothesis)
/// lives on the kernel side, wired in via this hook.
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
pub type CorruptionProbeFn = fn(addr: u64);
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
const CORRUPTION_PROBE_HOOK_NONE: u64 = 0;
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
static CORRUPTION_PROBE_HOOK: AtomicU64 = AtomicU64::new(CORRUPTION_PROBE_HOOK_NONE);

/// Register the corruption-probe hook (`debug-heappoison`/`debug-dealloc-diag`).
/// Idempotent: a later call replaces the prior hook. # C: O(1)
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
pub fn set_corruption_probe_hook(f: CorruptionProbeFn) {
    CORRUPTION_PROBE_HOOK.store((f as usize) as u64, Ordering::Release);
}

/// Invoke the corruption-probe hook if one is installed. # C: O(1) + hook cost
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
pub(crate) fn probe_corruption(addr: usize) {
    let raw = CORRUPTION_PROBE_HOOK.load(Ordering::Acquire);
    if raw == CORRUPTION_PROBE_HOOK_NONE { return; }
    // SAFETY: only ever stored by `set_corruption_probe_hook` from a
    // `CorruptionProbeFn`; the round-trip cast restores the fn-pointer's ABI.
    let f: CorruptionProbeFn = unsafe { core::mem::transmute(raw as usize) };
    f(addr as u64);
}

/// B1347: current-execution-context hook. The kernel installs a fn that packs
/// the running task's identity: bits[63:48]=`preempt_count` (nonzero above the
/// low preempt byte ⇒ hard/soft-IRQ context — the KEY discriminator for the
/// user's "unprotected interrupt writes" hypothesis), bits[47:24]=`last_syscall_nr`,
/// bits[23:0]=`tid`; `u64::MAX` = no current task (very-early boot / idle).
/// Read at a corruption CAUGHT by `periodic_validate_diag` — which walks the
/// whole free list every `DIAG_VALIDATE_INTERVAL` deallocs, so detection fires
/// within a few ops of the stale write. That names the WRITER's context, not
/// the eventual crash site (the zram disksize allocator merely STUMBLES on the
/// already-corrupt free list millions of ops later).
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
static CURRENT_CTX_HOOK: AtomicU64 = AtomicU64::new(0);
/// Install the current-context hook (kernel side, has sched access). # C: O(1)
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
pub fn set_current_ctx_hook(f: fn() -> u64) { CURRENT_CTX_HOOK.store(f as usize as u64, Ordering::Release); }
/// Packed running-context word (see `CURRENT_CTX_HOOK`), or 0 if no hook.
/// # C: O(1)+hook
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
pub(crate) fn current_ctx() -> u64 {
    let raw = CURRENT_CTX_HOOK.load(Ordering::Acquire);
    if raw == 0 { return 0; }
    // SAFETY: only ever stored by `set_current_ctx_hook` from a `fn() -> u64`.
    let f: fn() -> u64 = unsafe { core::mem::transmute(raw as usize) };
    f()
}

/// B1347: hook returning `(IRQ_SEQ << 8) | last_vec` from the arch IRQ dispatcher
/// (installed kernel-side). Recorded per kalloc op and printed at a detection so
/// a jump in IRQ_SEQ between the last clean op and the detection proves a HARD
/// IRQ fired in the write window (which preempt_count's hardirq bits don't track).
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
static IRQ_INFO_HOOK: AtomicU64 = AtomicU64::new(0);
/// Install the IRQ-info hook (kernel side, reads arch-irq IRQ_SEQ/last-vec). # C: O(1)
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
pub fn set_irq_info_hook(f: fn() -> u64) { IRQ_INFO_HOOK.store(f as usize as u64, Ordering::Release); }
/// `(IRQ_SEQ << 8) | last_vec`, or 0 if no hook. # C: O(1)+hook
#[cfg(feature = "debug-dealloc-diag")]
pub(crate) fn irq_info() -> u64 {
    let raw = IRQ_INFO_HOOK.load(Ordering::Acquire);
    if raw == 0 { return 0; }
    // SAFETY: only ever stored by `set_irq_info_hook` from a `fn() -> u64`.
    let f: fn() -> u64 = unsafe { core::mem::transmute(raw as usize) };
    f()
}
