// Kernel heap allocator (`kalloc`).
//
// `KAlloc` is a `GlobalAlloc` implementation backed by a sorted hole-list
// (`holes::HoleList`) with a `Spinlock<HoleList, KMalloc>` guard. The
// `KMalloc` lock class is the leaf of the partial order (`06§3.6`); any
// other subsystem may hold its own lock and call into kalloc, but kalloc
// never calls back into them.
//
// Boot sets up a single fixed-size BSS heap (`STATIC_HEAP_SIZE`) and
// hands its byte range to `KAlloc::init`. Future revisions per `12§2`
// will replace the static heap with PMM-backed slab size-class routing
// once a kernel binary stage exists; the public `GlobalAlloc` surface
// stays.
//
// Hosted tests instantiate fresh `KAlloc` instances over their own
// `Vec<u8>` buffers — no global state.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sync::{KMalloc, Spinlock, MAX_CPUS};

mod holes;
pub use holes::{HoleList, HoleListError, MIN_HOLE_ALIGN, MIN_HOLE_SIZE};

#[cfg(feature = "debug-dealloc-diag")]
mod size_track;

#[cfg(feature = "debug-heappoison")]
mod poison;
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
mod caller;
/// No architectural free-site address is available for this diagnostic. # C: O(1)
pub const UAF_FREE_IP_UNKNOWN: u64 = 0;
/// Diagnostic (`debug-heappoison`): if `addr` points into a currently
/// quarantined (freed-but-poisoned) block, return its `(base, size, free_ip)`. A hit
/// means `addr` is a use-after-free; `size` names the victim's type. Always
/// present so the arch fault handler can call it unconditionally; returns
/// `None` (ring empty) when the feature is off.
/// # C: O(QN) when armed, O(1) otherwise
#[cfg(feature = "debug-heappoison")]
pub fn uaf_lookup(addr: u64) -> Option<(u64, u32, u64)> {
    let raw = GLOBAL_ALLOC.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: `install_global` accepts only a kernel-lifetime static allocator.
    let alloc = unsafe { &*(raw as *const KAlloc) };
    let state = alloc.inner.lock();
    state.quarantine.lookup(addr)
}
#[cfg(not(feature = "debug-heappoison"))]
pub fn uaf_lookup(_addr: u64) -> Option<(u64, u32, u64)> { None }

/// Diagnostic (`debug-heappoison`): provenance for an address that is no
/// longer quarantined (`uaf_lookup` misses it) but WAS recently evicted back
/// to the real hole list. Names "what used to live here" for a corrupt
/// free-list node discovered long after the fact, when the corrupting write
/// itself was never caught live. # C: O(EVICT_HISTORY_SLOTS)
#[cfg(feature = "debug-heappoison")]
pub fn evicted_lookup(addr: u64) -> Option<(u64, u32, u64)> {
    let raw = GLOBAL_ALLOC.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: `install_global` accepts only a kernel-lifetime static allocator.
    let alloc = unsafe { &*(raw as *const KAlloc) };
    let state = alloc.inner.lock();
    state.holes.lookup_evicted(addr as usize).map(|(base, size, ip)| (base as u64, size, ip))
}
#[cfg(not(feature = "debug-heappoison"))]
pub fn evicted_lookup(_addr: u64) -> Option<(u64, u32, u64)> { None }

/// Diagnostic (`debug-heappoison`) bisection checkpoint: walk the installed
/// global allocator's free list right now and return the first corrupt
/// node's address, if any. Callers sprinkle this at boot checkpoints to
/// localize WHEN corruption first appears rather than where a later,
/// unrelated `alloc` happens to trip over it. `None` if uninstalled or intact.
/// # C: O(N)
#[cfg(feature = "debug-heappoison")]
pub fn validate_global() -> Option<usize> {
    let raw = GLOBAL_ALLOC.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: `install_global` accepts only a kernel-lifetime static allocator.
    let alloc = unsafe { &*(raw as *const KAlloc) };
    alloc.validate_now()
}

/// Heap size carved out of BSS for the kernel's static heap. 64 MiB
/// covers early-boot subsystems (vmm VMA tree, sched runqueues, vfs
/// dentry cache) BEFORE the PMM grow hook is wired (kmain); after that,
/// overflow routes to PMM-backed pages via `set_grow_hook` per `12§2`.
pub const STATIC_HEAP_SIZE: usize = 64 * MIB;

/// Bytes in 1 MiB.
pub const MIB: usize = 1024 * 1024;

/// Minimum grow-callback request size — avoid thrashing the PMM with
/// tiny grows by always pulling a 1 MiB chunk.
pub const GROW_CHUNK_MIN: usize = 1 * MIB;

/// No explicit memcg allocation owner. Valid only for pre-init and
/// kernel-global domains; known owners must enter `AllocationContext`.
/// # C: O(1)
pub const NO_MEMCG_CONTEXT: u64 = 0;

/// Explicit owner for heap growth. Context is CPU-local and nestable; a
/// nested scope restores its exact predecessor on drop. KAlloc remains
/// cgroup-independent; its PMM growth callback owns typed accounting.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AllocationContext { memcg: u64 }

impl AllocationContext {
    /// Intentionally uncharged boot/global allocation domain. # C: O(1)
    pub const UNCHARGED: Self = Self { memcg: NO_MEMCG_CONTEXT };
    /// Build an explicit cgroup-owned allocation domain. # C: O(1)
    pub const fn memcg(memcg: u64) -> Self { Self { memcg } }
    /// Cgroup identity carried to PMM growth. # C: O(1)
    pub const fn memcg_id(self) -> u64 { self.memcg }
}

/// Bump-aligned BSS storage. `align(4096)` keeps the heap page-aligned
/// so future mappings can be relaxed at page granularity.
#[repr(C, align(4096))]
struct StaticHeap(UnsafeCell<MaybeUninit<[u8; STATIC_HEAP_SIZE]>>);

// SAFETY: cross-thread access is mediated by `KAlloc`'s internal
// Spinlock; the raw bytes are uninitialized BSS and only handed out
// via `KAlloc::init_static`.
unsafe impl Sync for StaticHeap {}

static STATIC_HEAP: StaticHeap = StaticHeap(UnsafeCell::new(MaybeUninit::uninit()));
static GLOBAL_ALLOC: AtomicU64 = AtomicU64::new(0);

/// All mutable allocator ownership state. A block lives in exactly one of the
/// hole list (free), the quarantine (debug-held), or caller ownership (live).
struct AllocState {
    holes: HoleList,
    #[cfg(feature = "debug-heappoison")]
    quarantine: poison::Quar,
    /// Bounded live-allocation size ledger (`debug-dealloc-diag`) — see
    /// `size_track.rs`. Lives here so it's protected by the same lock as
    /// `holes`, with zero extra locking.
    #[cfg(feature = "debug-dealloc-diag")]
    size_track: size_track::SizeTrack,
}

impl AllocState {
    const fn new() -> Self {
        Self {
            holes: HoleList::new(),
            #[cfg(feature = "debug-heappoison")]
            quarantine: poison::Quar::new(),
            #[cfg(feature = "debug-dealloc-diag")]
            size_track: size_track::SizeTrack::new(),
        }
    }
}

/// Heap allocator. Construct with `KAlloc::new()` (const), then call
/// `init` once at boot before any allocation.
pub struct KAlloc {
    inner: Spinlock<AllocState, KMalloc>,
    initialized: AtomicBool,
    grow_hook: AtomicU64,
    /// Arch IRQ save-and-disable hook (`fn() -> u64`, returns the prior flags).
    /// `0` = not installed → no-op (early boot runs IRQ-off already).
    irq_save: AtomicU64,
    /// Arch IRQ restore hook (`fn(u64)`). Paired with `irq_save`.
    irq_restore: AtomicU64,
    context_cpu: AtomicU64,
    contexts: [AtomicU64; MAX_CPUS],
    context_required: AtomicBool,
    /// Diagnostic (`debug-heappoison`) op counter: every `VALIDATE_INTERVAL`th
    /// alloc/dealloc runs a full free-list `validate()`. Per-execve checkpoints
    /// alone leave a wide window between "corruption happened" and "a syscall
    /// boundary noticed" — this tightens detection to within one interval of
    /// ops, at the cost of O(N) work every `VALIDATE_INTERVAL` calls.
    #[cfg(feature = "debug-heappoison")]
    validate_countdown: AtomicU64,
    /// B1347: dealloc-diag full-free-list validation countdown (see
    /// `periodic_validate_diag`).
    #[cfg(feature = "debug-dealloc-diag")]
    validate_countdown_diag: AtomicU64,
    /// B1347: address of the last-reported corrupt node, to dedup repeat logs
    /// of a not-yet-overwritten bad node.
    #[cfg(feature = "debug-dealloc-diag")]
    last_bad_diag: AtomicU64,
}

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
fn next_seq() -> u64 { KALLOC_SEQ.fetch_add(1, Ordering::Relaxed) }

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

/// Callback signature for `set_watchpoint_hook` (`debug-hw-watchpoint`):
/// arm a hardware write-watchpoint on the just-freed HoleHdr-sized block at
/// byte `addr`. kalloc has no HAL/debug-register dependency, so the actual
/// DR0/DR1 arming lives kernel-side (`pmm::boot::watchpoint_arm`) and is
/// wired in through this hook, mirroring `CorruptionProbeFn`.
#[cfg(feature = "debug-hw-watchpoint")]
pub type WatchpointArmFn = fn(addr: u64);
#[cfg(feature = "debug-hw-watchpoint")]
const WATCHPOINT_HOOK_NONE: u64 = 0;
#[cfg(feature = "debug-hw-watchpoint")]
static WATCHPOINT_HOOK: AtomicU64 = AtomicU64::new(WATCHPOINT_HOOK_NONE);

/// Register the free-block watchpoint hook (`debug-hw-watchpoint`).
/// Idempotent: a later call replaces the prior hook. # C: O(1)
#[cfg(feature = "debug-hw-watchpoint")]
pub fn set_watchpoint_hook(f: WatchpointArmFn) {
    WATCHPOINT_HOOK.store((f as usize) as u64, Ordering::Release);
}

/// Address currently covered by the armed watchpoint, or 0 if none. Lets
/// `alloc()`'s success path tell "this exact block was just legitimately
/// carved back out" (expected, disarm and stay quiet) from "something else
/// wrote to a block kalloc still considers free" (the actual signal).
#[cfg(feature = "debug-hw-watchpoint")]
static WATCHPOINT_ARMED_ADDR: AtomicU64 = AtomicU64::new(0);

/// Callback signature for `set_watchpoint_disarm_hook`: clear the armed
/// hardware watchpoint (DR7 local-enable bits off). No address needed —
/// there is only ever one armed watchpoint (v1 single-block scope).
#[cfg(feature = "debug-hw-watchpoint")]
pub type WatchpointDisarmFn = fn();
#[cfg(feature = "debug-hw-watchpoint")]
static WATCHPOINT_DISARM_HOOK: AtomicU64 = AtomicU64::new(WATCHPOINT_HOOK_NONE);

/// Register the watchpoint-disarm hook (`debug-hw-watchpoint`).
/// # C: O(1)
#[cfg(feature = "debug-hw-watchpoint")]
pub fn set_watchpoint_disarm_hook(f: WatchpointDisarmFn) {
    WATCHPOINT_DISARM_HOOK.store((f as usize) as u64, Ordering::Release);
}

/// Arm the watchpoint hook on a just-freed block, if one is installed.
/// # C: O(1) + hook cost
#[cfg(feature = "debug-hw-watchpoint")]
pub(crate) fn arm_watchpoint(addr: usize) {
    let raw = WATCHPOINT_HOOK.load(Ordering::Acquire);
    if raw == WATCHPOINT_HOOK_NONE { return; }
    WATCHPOINT_ARMED_ADDR.store(addr as u64, Ordering::Release);
    // SAFETY: only ever stored by `set_watchpoint_hook` from a
    // `WatchpointArmFn`; the round-trip cast restores the fn-pointer's ABI.
    let f: WatchpointArmFn = unsafe { core::mem::transmute(raw as usize) };
    f(addr as u64);
}

/// Disarm the watchpoint if `alloc_addr` is exactly the currently-armed
/// block — proof that `alloc()`'s own carve/first-fit legitimately reclaimed
/// it, not a stale-pointer write. Leaves it armed (and thus still watching)
/// for any other address, since that means the armed block is STILL
/// sitting unclaimed on the free list.
/// # C: O(1) + hook cost
#[cfg(feature = "debug-hw-watchpoint")]
pub(crate) fn disarm_watchpoint_if_reclaimed(alloc_addr: usize) {
    let armed = WATCHPOINT_ARMED_ADDR.load(Ordering::Acquire);
    if armed == 0 || armed != alloc_addr as u64 { return; }
    WATCHPOINT_ARMED_ADDR.store(0, Ordering::Release);
    let raw = WATCHPOINT_DISARM_HOOK.load(Ordering::Acquire);
    if raw == WATCHPOINT_HOOK_NONE { return; }
    // SAFETY: only ever stored by `set_watchpoint_disarm_hook` from a
    // `WatchpointDisarmFn`; the round-trip cast restores the fn-pointer's ABI.
    let f: WatchpointDisarmFn = unsafe { core::mem::transmute(raw as usize) };
    f();
}

/// Unconditionally disarm the watchpoint. Called at the START of every alloc
/// AND dealloc so kalloc's OWN free-list header writes (coalesce / split /
/// `add_free_region`) do NOT `#DB`-trap as false positives — the watchpoint is
/// only armed BETWEEN kalloc ops, so exclusively an EXTERNAL stale-pointer
/// write to a still-free block faults (the corruptor). dealloc re-arms on the
/// freshly-freed block at its exit. Also stops the false-positive fault storm
/// that otherwise slows the boot below the corruption window.
/// # C: O(1) + hook cost
#[cfg(feature = "debug-hw-watchpoint")]
pub(crate) fn disarm_watchpoint_now() {
    if WATCHPOINT_ARMED_ADDR.swap(0, Ordering::AcqRel) == 0 { return; }
    let raw = WATCHPOINT_DISARM_HOOK.load(Ordering::Acquire);
    if raw == WATCHPOINT_HOOK_NONE { return; }
    // SAFETY: only ever stored by `set_watchpoint_disarm_hook` from a
    // `WatchpointDisarmFn`; the round-trip cast restores the fn-pointer's ABI.
    let f: WatchpointDisarmFn = unsafe { core::mem::transmute(raw as usize) };
    f();
}

/// Ops between periodic free-list validations (`debug-heappoison`). Small
/// enough to localize corruption to a tight window; large enough that the
/// O(N) walk isn't the hot path. Tightened from 64: two live corruption
/// captures this session were both caught lazily by `try_merge` instead of
/// by this periodic check, meaning the corruption happened within one
/// 64-op window of detection — narrower still means a real chance at
/// `last_op_ip` naming the actual corrupting call instead of an unrelated
/// later caller that merely stumbled into the already-trashed node.
#[cfg(feature = "debug-heappoison")]
const VALIDATE_INTERVAL: u64 = 8;

/// B1347: `debug-dealloc-diag` full-free-list validation cadence. Coarser than
/// heappoison's every-8 (no per-block poison memset here, but the walk is still
/// O(free-nodes)), chosen so a fast `debug-boot,debug-dealloc-diag` boot stays
/// in the ~tens-of-seconds range while narrowing corruption-to-detection from
/// "millions of ops (until zram stumbles)" to "≤32 deallocs of the stale write".
#[cfg(feature = "debug-dealloc-diag")]
const DIAG_VALIDATE_INTERVAL: u64 = 32;

/// RAII allocation-domain scope. The caller keeps preemption disabled until
/// drop, pinning the CPU whose context slot is restored.
pub struct AllocationScope<'a> {
    alloc: &'a KAlloc,
    cpu: usize,
    prior: u64,
}

/// Scope for the kernel's canonical global allocator.
pub struct GlobalAllocationScope { _scope: AllocationScope<'static> }

impl Drop for AllocationScope<'_> {
    fn drop(&mut self) { self.alloc.contexts[self.cpu].store(self.prior, Ordering::Release); }
}

/// RAII: IRQs are disabled for the whole enclosing alloc/dealloc and restored
/// on drop (every return path). The kernel heap is shared with IRQ-context
/// allocators — the timer-ISR deferred-wake path pushes an `Arc<Task>` to a
/// per-CPU `Vec` that can realloc → `KAlloc::alloc` inside a hard IRQ. Under the
/// plain (non-IRQ) `Spinlock` that deadlocks (the ISR spins on the lock the
/// interrupted mainline holds) or, in the grow window, re-enters and races the
/// hole list. Disabling IRQs across the ENTIRE op (not just while the hole-list
/// lock is held — the grow path drops it to call the PMM) closes both.
struct IrqOff {
    restore: u64,
    flags: u64,
}
impl Drop for IrqOff {
    fn drop(&mut self) {
        if self.restore != 0 {
            // SAFETY: `restore` was stored from a `fn(u64)` via set_irq_gate;
            // `flags` is the value the paired save hook returned.
            let f: fn(u64) = unsafe { core::mem::transmute(self.restore as usize) };
            f(self.flags);
        }
    }
}

impl KAlloc {
    /// Construct an uninitialized allocator. `init` must be called
    /// before any `alloc` / `dealloc` reaches this instance.
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            inner: Spinlock::new(AllocState::new()),
            initialized: AtomicBool::new(false),
            grow_hook: AtomicU64::new(GROW_HOOK_NONE),
            irq_save: AtomicU64::new(0),
            irq_restore: AtomicU64::new(0),
            context_cpu: AtomicU64::new(0),
            contexts: [const { AtomicU64::new(NO_MEMCG_CONTEXT) }; MAX_CPUS],
            context_required: AtomicBool::new(false),
            #[cfg(feature = "debug-heappoison")]
            validate_countdown: AtomicU64::new(VALIDATE_INTERVAL),
            #[cfg(feature = "debug-dealloc-diag")]
            validate_countdown_diag: AtomicU64::new(DIAG_VALIDATE_INTERVAL),
            #[cfg(feature = "debug-dealloc-diag")]
            last_bad_diag: AtomicU64::new(0),
        }
    }

    /// B1347 diagnostic: every `DIAG_VALIDATE_INTERVAL`th dealloc, walk the whole
    /// free list and, on the FIRST corrupt node (deduped by address so a
    /// not-yet-overwritten bad node logs once), print the running context that
    /// the stale write happened under — packed `current_ctx()` decoded into
    /// tid / last_syscall / preempt_count / in-IRQ — plus the node's free-IP
    /// provenance. Does NOT panic: boot continues so the eventual zram-stumble
    /// crash still appears and can be correlated with the early context capture.
    /// # C: amortized O(1), O(N) on tick
    #[cfg(feature = "debug-dealloc-diag")]
    fn periodic_validate_diag(&self, op_ip: u64) {
        if self.validate_countdown_diag.fetch_sub(1, Ordering::AcqRel) != 1 { return; }
        self.validate_countdown_diag.store(DIAG_VALIDATE_INTERVAL, Ordering::Release);
        // Bind+drop the guard before logging (same lifetime-extension / panic-path
        // re-entrancy reasoning as `periodic_validate`).
        let bad = self.inner.lock().holes.validate();
        let Some(bad) = bad else { return; };
        if self.last_bad_diag.swap(bad as u64, Ordering::AcqRel) == bad as u64 { return; }
        // Packed by the kernel hook: bits[63:40]=preempt_count(24), [39:20]=syscall(20),
        // [19:0]=tid(20). `u64::MAX` = no current task.
        let ctx = current_ctx();
        let preempt = (ctx >> 40) & 0xFF_FFFF;
        klog::write_primary_raw(b"[KALLOC] seq=");
        klog::write_primary_dec_u64(next_seq());
        klog::write_primary_raw(b" diag-validate-failed bad_node=0x");
        klog::write_primary_hex_u64(bad as u64);
        klog::write_primary_raw(b" last_op_ip=0x");
        klog::write_primary_hex_u64(op_ip);
        klog::write_primary_raw(b" ctx.tid=");
        klog::write_primary_dec_u64(ctx & 0xF_FFFF);
        klog::write_primary_raw(b" ctx.syscall=");
        klog::write_primary_dec_u64((ctx >> 20) & 0xF_FFFF);
        klog::write_primary_raw(b" ctx.preempt=0x");
        klog::write_primary_hex_u64(preempt);
        // in_irq: any softirq(8-15)/hardirq(16-19)/nmi bit above the low preempt byte.
        klog::write_primary_raw(b" ctx.in_irq=");
        klog::write_primary_dec_u64(((preempt >> 8) != 0) as u64);
        klog::write_primary_raw(b"\n");
        // Provenance of the corrupt node + PMM classification of its address.
        self.inner.lock().holes.print_free_ip(bad);
        probe_corruption(bad);
    }

    /// Diagnostic (`debug-heappoison`) periodic integrity check: every
    /// `VALIDATE_INTERVAL`th call runs a full free-list `validate()` and
    /// panics naming the bad node immediately, instead of waiting for a
    /// later unrelated `alloc`/merge to trip over already-stale corruption.
    /// Tightens the corruption-to-detection window from "one execve" to
    /// "one interval of alloc/dealloc calls". # C: amortized O(1), O(N) on tick
    #[cfg(feature = "debug-heappoison")]
    fn periodic_validate(&self, op_ip: u64) {
        if self.validate_countdown.fetch_sub(1, Ordering::AcqRel) != 1 { return; }
        self.validate_countdown.store(VALIDATE_INTERVAL, Ordering::Release);
        // `if let Some(bad) = self.inner.lock().holes.validate() { ... }` would
        // extend the lock guard's temporary lifetime across the whole block
        // (Rust's if-let temporary-lifetime-extension) -- holding this lock
        // while `assert!` panics below. The panic handler's own klog path can
        // reach a framebuffer console scroll that allocates, which would then
        // self-deadlock reacquiring this same lock on this same CPU: a silent
        // hang with the diagnostic print as the last-ever output, instead of a
        // visible panic. Bind and drop explicitly before asserting.
        let bad = self.inner.lock().holes.validate();
        if let Some(bad) = bad {
            klog::write_primary_raw(b"[KALLOC] seq=");
            klog::write_primary_dec_u64(next_seq());
            klog::write_primary_raw(b" periodic-validate-failed bad_node=");
            klog::write_primary_hex_u64(bad as u64);
            klog::write_primary_raw(b" last_op_ip=");
            klog::write_primary_hex_u64(op_ip);
            klog::write_primary_raw(b"\n");
            probe_corruption(bad);
            assert!(false, "kalloc periodic validate failed");
        }
    }

    /// Install the arch IRQ save-disable / restore hooks so `alloc`/`dealloc`
    /// run IRQ-atomic (see `IrqOff`). Called once at boot after IRQs exist.
    /// # C: O(1)
    pub fn set_irq_gate(&self, save: fn() -> u64, restore: fn(u64)) {
        self.irq_save.store(save as usize as u64, Ordering::Release);
        self.irq_restore.store(restore as usize as u64, Ordering::Release);
    }

    /// Install per-CPU identity accessor used by allocation scopes. # C: O(1)
    pub fn set_context_cpu_hook(&self, current_cpu: fn() -> u16) {
        self.context_cpu.store(current_cpu as usize as u64, Ordering::Release);
    }

    /// Publish this kernel-lifetime allocator as the sole context owner.
    /// # C: O(1)
    pub fn install_global(&'static self) { GLOBAL_ALLOC.store(self as *const Self as u64, Ordering::Release); }

    /// Reject post-init heap growth with no explicit allocation context.
    /// # C: O(1)
    pub fn require_context_for_growth(&self) { self.context_required.store(true, Ordering::Release); }

    /// Walk the whole free list now and report the first corrupt node, if
    /// any. Diagnostic-only bisection checkpoint: call at several points
    /// during boot to localize WHEN the free list first breaks, rather than
    /// waiting for the next unrelated `alloc`/`dealloc` to trip a reactive
    /// assert far downstream of the actual corruption. # C: O(N)
    #[cfg(feature = "debug-heappoison")]
    pub fn validate_now(&self) -> Option<usize> { self.inner.lock().holes.validate() }

    /// Print the free list's (addr, size) layout right now, capped at
    /// `cap` entries. Diagnostic-only (debug-heappoison): names the
    /// allocation adjacent to a corrupted node in address order. # C: O(cap)
    #[cfg(feature = "debug-heappoison")]
    pub fn dump_now(&self, cap: usize) { self.inner.lock().holes.dump(cap); }

    /// Enter explicit CPU-local allocation domain. Nested scopes restore the
    /// exact prior owner. # C: O(1)
    /// # Ctx: preempt-disabled until the returned scope drops
    pub fn enter_context(&self, context: AllocationContext) -> AllocationScope<'_> {
        let cpu = self.context_cpu();
        let prior = self.contexts[cpu].swap(context.memcg_id(), Ordering::AcqRel);
        AllocationScope { alloc: self, cpu, prior }
    }

    /// Current CPU's growth owner, or no owner for pre-init/global work.
    /// # C: O(1)
    pub fn active_memcg(&self) -> u64 { self.contexts[self.context_cpu()].load(Ordering::Acquire) }

    /// Disable IRQs for the caller's scope (RAII); no-op until `set_irq_gate`.
    #[inline]
    fn irq_off(&self) -> IrqOff {
        let s = self.irq_save.load(Ordering::Acquire);
        let r = self.irq_restore.load(Ordering::Acquire);
        if s == 0 || r == 0 { return IrqOff { restore: 0, flags: 0 }; }
        // SAFETY: `s` was stored from a `fn() -> u64` via set_irq_gate.
        let save: fn() -> u64 = unsafe { core::mem::transmute(s as usize) };
        IrqOff { restore: r, flags: save() }
    }

    fn context_cpu(&self) -> usize {
        let raw = self.context_cpu.load(Ordering::Acquire);
        if raw == 0 { return 0; }
        // SAFETY: set_context_cpu_hook stores only this function-pointer ABI.
        let current: fn() -> u16 = unsafe { core::mem::transmute(raw as usize) };
        let cpu = current() as usize;
        assert!(cpu < MAX_CPUS, "kalloc context cpu out of range");
        cpu
    }

    /// Set up the allocator over `[start, start + size)`.
    ///
    /// # SAFETY: caller asserts the byte range is exclusively owned by
    /// this allocator for the rest of program lifetime, fully writable,
    /// and not aliased by any live reference. Must be called exactly
    /// once before the first allocation.
    /// # C: O(1)
    /// # Ctx: pre-init, IRQ-off, single-CPU
    pub unsafe fn init(&self, start: usize, size: usize) {
        let mut g = self.inner.lock();
        // SAFETY: caller-asserted exclusive ownership of [start, start+size).
        assert!(unsafe { g.holes.add_region(start, size) }.is_ok(), "kalloc init region invalid");
        drop(g);
        self.initialized.store(true, Ordering::Release);
    }

    /// Initialize from the built-in static BSS heap. Convenience wrapper
    /// over `init`; same one-shot, exclusive-ownership contract.
    ///
    /// # SAFETY: caller is the boot path; the static heap must not
    /// already be in use.
    /// # C: O(1)
    /// # Ctx: pre-init
    pub unsafe fn init_static(&self) {
        let ptr = STATIC_HEAP.0.get() as *mut u8 as usize;
        // SAFETY: caller-asserted exclusivity; STATIC_HEAP lives for the
        // process lifetime.
        unsafe { self.init(ptr, STATIC_HEAP_SIZE) };
    }

    /// True iff `init` has been called.
    /// # C: O(1)
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }
}

/// Enter the sole installed kernel allocator's explicit context. `None` is
/// permitted only before allocator publication during boot. # C: O(1)
pub fn enter_global_context(context: AllocationContext) -> Option<GlobalAllocationScope> {
    let raw = GLOBAL_ALLOC.load(Ordering::Acquire);
    if raw == 0 { return None; }
    // SAFETY: install_global accepts only a kernel-lifetime static allocator.
    let alloc = unsafe { &*(raw as *const KAlloc) };
    Some(GlobalAllocationScope { _scope: alloc.enter_context(context) })
}

/// Replace the scheduler-installed context for this CPU. # C: O(1)
/// # Ctx: preempt-disabled task-switch boundary
pub fn replace_global_context(context: AllocationContext) -> bool {
    let raw = GLOBAL_ALLOC.load(Ordering::Acquire);
    if raw == 0 { return false; }
    // SAFETY: install_global accepts only a kernel-lifetime static allocator.
    let alloc = unsafe { &*(raw as *const KAlloc) };
    let cpu = alloc.context_cpu();
    alloc.contexts[cpu].store(context.memcg_id(), Ordering::Release);
    true
}

impl Default for KAlloc {
    fn default() -> Self { Self::new() }
}

/// T16 (F247) growable kernel heap: when the hole-list allocator can't
/// satisfy a request, fall back to a registered grow callback that
/// asks the PMM for more pages and feeds them to the hole list.
/// Linux's vmalloc equivalent; without it the kernel OOMs on any
/// single workload bigger than the static heap can hold.
///
/// Callback signature: takes the minimum extra bytes needed; returns
/// `(start_addr, size_bytes)` of a fresh region added to the hole
/// list, or `None` if no more memory is available. The callback owns
/// the lifetime of the region — it must stay valid until process
/// shutdown.
pub type GrowFn = fn(min_extra: usize, memcg: u64) -> Option<(usize, usize)>;

/// Sentinel "no hook installed" stored in `KAlloc::grow_hook`.
const GROW_HOOK_NONE: u64 = 0;

impl KAlloc {
    /// Register a callback the alloc path invokes when the hole-list
    /// can't satisfy a request. Idempotent: a later call replaces the
    /// prior hook.
    /// # SAFETY: `f` must remain a valid fn-pointer for the lifetime
    /// of this allocator; the kernel never unloads it.
    /// # C: O(1)
    pub fn set_grow_hook(&self, f: GrowFn) {
        let raw = (f as usize) as u64;
        self.grow_hook.store(raw, Ordering::Release);
    }
}

// SAFETY: `KAlloc::alloc` returns either null or a NonNull pointing
// into the heap region the caller passed to `init`. `dealloc` accepts
// only pointers that came from `alloc`; both paths take the inner
// Spinlock so the hole list mutations are serialized.
unsafe impl GlobalAlloc for KAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !self.is_initialized() { return ptr::null_mut(); }
        // Diagnostic-only (debug-heappoison): carve a trailing redzone onto
        // every allocation so a heap buffer OVERFLOW (a write past the
        // caller's own requested bytes, into the next allocation) is caught
        // at free time instead of silently landing on whatever neighbor
        // happens to be there — the exact "wild write, unrelated victim"
        // shape this session's zram/heap-corruption hunt keeps finding.
        // Falls back to the plain layout if the redzone addition would
        // overflow (astronomically large request; safe to just not pad it).
        #[cfg(feature = "debug-heappoison")]
        let carve_layout = poison::alloc_layout(layout).unwrap_or(layout);
        #[cfg(not(feature = "debug-heappoison"))]
        let carve_layout = layout;
        // IRQ-atomic across the WHOLE alloc (incl. the unlocked grow window).
        let _irq = self.irq_off();
        // Disarm before this op touches the hole list, so kalloc's own header
        // writes (split/coalesce) don't self-trip the freed-block watchpoint.
        #[cfg(feature = "debug-hw-watchpoint")]
        disarm_watchpoint_now();
        let mut g = self.inner.lock();
        if let Some(p) = g.holes.alloc(carve_layout) {
            #[cfg(feature = "debug-dealloc-diag")]
            g.size_track.record(p.as_ptr() as usize, carve_layout.size());
            // B1346: record the alloc-return-IP so a later corruption of this
            // block (once freed) names the recycled victim's type + the writer's
            // (prev-alloc) type.
            #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
            g.holes.record_alloc_ip(p.as_ptr() as usize, caller::alloc_return_ip());
            drop(g);
            // B1347: tick the diag validator on ALLOC too. The boot corruptor
            // manifests inside the zram-disksize ALLOC burst (compressor init +
            // slots.resize), where a dealloc-only tick never runs — so validate
            // catches the first bad free node within a few allocs of creation
            // and names the running context (see periodic_validate_diag).
            #[cfg(feature = "debug-dealloc-diag")]
            self.periodic_validate_diag(caller::alloc_return_ip());
            #[cfg(feature = "debug-heappoison")]
            {
                // SAFETY: `p` was just carved with `carve_layout`'s extra
                // trailing bytes reserved exactly for this redzone.
                unsafe { poison::arm_redzone(p.as_ptr(), layout); }
                self.periodic_validate(caller::UNKNOWN_RETURN_IP);
            }
            #[cfg(feature = "debug-hw-watchpoint")]
            disarm_watchpoint_if_reclaimed(p.as_ptr() as usize);
            return p.as_ptr();
        }
        // `klog` fans out to framebuffer consoles, whose scroll path can
        // allocate. Release the heap lock before diagnostics or PMM growth so
        // that diagnostic output cannot recursively spin on this lock.
        drop(g);
        #[cfg(feature = "debug-heappoison")]
        {
            klog::write_primary_raw(b"[KALLOC] allocation-miss bytes=");
            klog::write_primary_dec_u64(carve_layout.size() as u64);
            klog::write_primary_raw(b" align=");
            klog::write_primary_dec_u64(carve_layout.align() as u64);
            klog::write_primary_raw(b"\n");
        }
        // T16: hole-list couldn't satisfy. Try the grow hook.
        let raw = self.grow_hook.load(Ordering::Acquire);
        if raw == GROW_HOOK_NONE {
            #[cfg(feature = "debug-heappoison")]
            klog::write_primary_raw(b"[KALLOC] growth-unavailable no-hook\n");
            return ptr::null_mut();
        }
        let memcg = self.active_memcg();
        if memcg == NO_MEMCG_CONTEXT && self.context_required.load(Ordering::Acquire) {
            #[cfg(feature = "debug-heappoison")]
            klog::write_primary_raw(b"[KALLOC] growth-unavailable no-context\n");
            return ptr::null_mut();
        }
        // SAFETY: stored only via set_grow_hook from a `GrowFn`; the
        // round-trip cast restores the fn-pointer's ABI.
        let f: GrowFn = unsafe { core::mem::transmute(raw as usize) };
        // Ask for at least the layout, with align headroom, rounded up
        // to GROW_CHUNK_MIN so we don't thrash the PMM with tiny grows.
        let need = carve_layout.size().saturating_add(carve_layout.align()).max(GROW_CHUNK_MIN);
        #[cfg(feature = "debug-heappoison")]
        {
            klog::write_primary_raw(b"[KALLOC] growth-request bytes=");
            klog::write_primary_dec_u64(need as u64);
            klog::write_primary_raw(b"\n");
        }
        let (addr, size) = match f(need, memcg) {
            Some(p) => {
                #[cfg(feature = "debug-heappoison")]
                {
                    klog::write_primary_raw(b"[KALLOC] growth-acquired addr=");
                    klog::write_primary_hex_u64(p.0 as u64);
                    klog::write_primary_raw(b" bytes=");
                    klog::write_primary_dec_u64(p.1 as u64);
                    klog::write_primary_raw(b"\n");
                }
                p
            }
            None    => {
                #[cfg(feature = "debug-heappoison")]
                klog::write_primary_raw(b"[KALLOC] growth-failed\n");
                return ptr::null_mut();
            }
        };
        let mut g = self.inner.lock();
        #[cfg(feature = "debug-heappoison")]
        g.holes.dump(256);
        // SAFETY: caller of the GrowFn (the kernel boot path) guarantees
        // exclusive ownership of [addr, addr + size); fully writable.
        let registered = unsafe { g.holes.add_region(addr, size) };
        let p = if registered.is_ok() { g.holes.alloc(carve_layout).map_or(ptr::null_mut(), |p| p.as_ptr()) } else { ptr::null_mut() };
        #[cfg(feature = "debug-dealloc-diag")]
        if !p.is_null() { g.size_track.record(p as usize, carve_layout.size()); }
        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
        if !p.is_null() { g.holes.record_alloc_ip(p as usize, caller::alloc_return_ip()); }
        drop(g);
        if let Err(_e) = registered {
            #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
            {
                klog::write_primary_raw(b"[KALLOC] growth-register-failed addr=");
                klog::write_primary_hex_u64(addr as u64);
                klog::write_primary_raw(b" size=");
                klog::write_primary_dec_u64(size as u64);
                klog::write_primary_raw(b" tag=");
                klog::write_primary_raw(_e.tag());
                klog::write_primary_raw(b"\n");
            }
            assert!(false, "kalloc grow region invalid");
        }
        #[cfg(feature = "debug-heappoison")]
        if !p.is_null() {
            // SAFETY: `p` was just carved with `carve_layout`'s extra
            // trailing bytes reserved exactly for this redzone.
            unsafe { poison::arm_redzone(p, layout); }
        }
        // B1347: validate right after a GROW carve — the large zram allocation
        // grows the heap, and a carve/region-boundary bug would first appear here.
        #[cfg(feature = "debug-dealloc-diag")]
        if !p.is_null() { self.periodic_validate_diag(caller::alloc_return_ip()); }
        #[cfg(feature = "debug-heappoison")]
        klog::write_primary_raw(b"[KALLOC] growth-registered\n");
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() { return; }
        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
        let free_ip = caller::dealloc_return_ip();
        // Diagnostic-only (debug-heappoison): must match `alloc`'s expansion
        // exactly (same deterministic function of `layout` alone) so the
        // hole-list reclaim covers the SAME span that was carved out,
        // trailing redzone included. Check the redzone BEFORE anything else
        // touches this block — a mismatch means ITS OWNER (not some later
        // reader) overflowed past its own requested bytes.
        #[cfg(feature = "debug-heappoison")]
        {
            // SAFETY: `ptr` was returned by this allocator's `alloc(layout)`,
            // which armed a redzone at `ptr+layout.size()` sized to fit
            // within `alloc_layout(layout)`'s padding.
            unsafe { poison::check_redzone(ptr, layout); }
        }
        #[cfg(feature = "debug-heappoison")]
        let carve_layout = poison::alloc_layout(layout).unwrap_or(layout);
        #[cfg(not(feature = "debug-heappoison"))]
        let carve_layout = layout;
        // IRQ-atomic: dealloc mutates the same hole list an IRQ-context alloc
        // touches; disable IRQs for the whole op (see `IrqOff`).
        let _irq = self.irq_off();
        // Disarm before this op touches the hole list (coalesce writes the
        // freed block's + neighbors' headers); re-armed on the final freed
        // block at exit, so only EXTERNAL writes between ops fault.
        #[cfg(feature = "debug-hw-watchpoint")]
        disarm_watchpoint_now();
        // SAFETY: caller-asserted that `ptr` was previously returned by
        // `alloc(layout)` and is no longer borrowed.
        let nn = unsafe { core::ptr::NonNull::new_unchecked(ptr) };
        // debug-heappoison: poison + quarantine small blocks (delay reuse) so a
        // UAF read hits 0xEE deterministically; only really free an evicted one.
        // Gated on the CALLER's requested size (not the carved/padded size) —
        // POISON_MAX is about the caller's own size class.
        #[cfg(feature = "debug-heappoison")]
        if layout.size() <= poison::POISON_MAX {
            let mut g = self.inner.lock();
            // Preflight while the same lock protects both ownership domains:
            // a stale release cannot poison an existing free-list header.
            assert!(!g.quarantine.contains(ptr, carve_layout), "kalloc duplicate quarantined free");
            assert!(g.holes.can_dealloc(nn, carve_layout).is_ok(), "kalloc invalid free");
            // Byte address of a block that became a genuine free HoleHdr this
            // call, to arm a hardware watchpoint on AFTER the lock drops.
            #[cfg(feature = "debug-hw-watchpoint")]
            let mut freed_hdr: Option<usize> = None;
            // SAFETY: preflight proved this allocation is neither free nor
            // quarantined, so the transition into the quarantine is exclusive.
            if let Some((vptr, vlayout)) = unsafe { poison::quarantine(&mut g.quarantine, ptr, carve_layout, free_ip) } {
                // Record provenance BEFORE reinsertion: once this span is a
                // real hole again, this is the last point anything knows
                // "what used to be here" for a corruption discovered later.
                g.holes.record_evicted(vptr as usize, vlayout.size() as u32, free_ip);
                // SAFETY: `vptr` was quarantined from a prior alloc via `quarantine`; now evicted, so reclaim it to the hole list.
                let vnn = unsafe { core::ptr::NonNull::new_unchecked(vptr) };
                // SAFETY: evicted quarantined block; re-insert into the hole list.
                assert!(unsafe { g.holes.dealloc(vnn, vlayout) }.is_ok(), "kalloc invalid free");
                #[cfg(feature = "debug-hw-watchpoint")]
                { freed_hdr = Some(vptr as usize); }
            }
            drop(g);
            // debug-hw-watchpoint: arm the write-watchpoint on the block that
            // just rejoined the free list (lock dropped — the hook reaches into
            // the arch debug-register path).
            #[cfg(feature = "debug-hw-watchpoint")]
            if let Some(a) = freed_hdr { arm_watchpoint(a); }
            self.periodic_validate(free_ip);
            return;
        }
        let mut g = self.inner.lock();
        // Bounded live-allocation size ledger (`debug-dealloc-diag`, see
        // `size_track.rs`): if this exact pointer was recorded at alloc
        // time with a DIFFERENT size than what's being freed with now, the
        // caller's Layout is wrong — `add_free_region` has no way to detect
        // this itself (it only checks the freed range against OTHER FREE
        // nodes, never against live neighbors), so an oversized dealloc
        // here silently corrupts whatever live allocation follows. This is
        // the direct, targeted check for that whole bug class.
        #[cfg(feature = "debug-dealloc-diag")]
        if let Some(recorded) = g.size_track.take(ptr as usize) {
            if recorded != carve_layout.size() {
                klog::write_primary_raw(b"[KALLOC] size-mismatch ptr=");
                klog::write_primary_hex_u64(ptr as u64);
                klog::write_primary_raw(b" alloc_size=");
                klog::write_primary_dec_u64(recorded as u64);
                klog::write_primary_raw(b" dealloc_size=");
                klog::write_primary_dec_u64(carve_layout.size() as u64);
                klog::write_primary_raw(b" dealloc_caller_ip=0x");
                klog::write_primary_hex_u64(caller::dealloc_return_ip());
                klog::write_primary_raw(b"\n");
                panic!("kalloc dealloc size mismatch");
            }
        }
        // B1346: record this block's dealloc-return-IP for corruption
        // provenance BEFORE dealloc coalesces/reinserts it. If this exact block
        // is later found corrupt as a free-list node, its last free-IP names
        // where the stale-pointer WRITER freed its own object (addr2line the IP).
        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
        g.holes.record_free_ip(ptr as usize, caller::dealloc_return_ip());
        // SAFETY: same as above; routed through HoleList::dealloc which
        // re-inserts the region into the sorted hole list.
        let dealloc_result = unsafe { g.holes.dealloc(nn, carve_layout) };
        // Print BEFORE the assert: this is the only diagnostic this
        // failure gets on a non-debug-heappoison build (the fast,
        // reliable ~15s smoke-profile repro of this session's corruption
        // hunt runs bare `debug-boot`, not `debug-heappoison` -- that
        // feature changes kalloc's internal timing enough to mask the
        // fast repro). Tag alone narrows MalformedNode/OverlappingFree/
        // OutsideOwnedRegion/AddressOverflow into very different
        // mechanisms.
        #[cfg(feature = "debug-dealloc-diag")]
        if let Err(e) = dealloc_result {
            klog::write_primary_raw(b"[KALLOC] dealloc-failed tag=");
            klog::write_primary_raw(e.tag());
            klog::write_primary_raw(b" ptr=");
            klog::write_primary_hex_u64(ptr as u64);
            klog::write_primary_raw(b" size=");
            klog::write_primary_dec_u64(carve_layout.size() as u64);
            klog::write_primary_raw(b" align=");
            klog::write_primary_dec_u64(carve_layout.align() as u64);
            klog::write_primary_raw(b"\n");
        }
        assert!(dealloc_result.is_ok(), "kalloc invalid free");
        drop(g);
        // debug-hw-watchpoint: `ptr` is now (part of) a genuine free HoleHdr.
        // Arm a hardware write-watchpoint over its 16 bytes so a later stray
        // kernel write to the freed node #DB-traps and names the writer. If
        // `ptr` coalesced into a lower-addressed neighbor it's mid-region
        // rather than the header, so this catches the (common, unmerged) case
        // where the freed block stays its own header — single most-recently-
        // freed block, per the v1 diagnostic scope.
        //
        // Size-filtered: a live first pass watching EVERY freed block was
        // pure noise (337 distinct call sites in one ~35s boot, all
        // resolving to kalloc's own add_free_region/memcpy legitimately
        // reusing the address moments later — kalloc serves every kernel
        // allocation, so small/hot sizes recycle within microseconds).
        // Only arm on blocks at/above WATCHPOINT_MIN_SIZE: large enough to
        // sit on the free list appreciably longer before legitimate reuse,
        // while still covering the 4128-byte victim this session's earlier
        // "kalloc invalid free ptr=... size=4128" sample named directly.
        #[cfg(feature = "debug-hw-watchpoint")]
        const WATCHPOINT_MIN_SIZE: usize = 512;
        #[cfg(feature = "debug-hw-watchpoint")]
        if carve_layout.size() >= WATCHPOINT_MIN_SIZE {
            arm_watchpoint(ptr as usize);
        }
        #[cfg(feature = "debug-heappoison")]
        self.periodic_validate(free_ip);
        #[cfg(feature = "debug-dealloc-diag")]
        self.periodic_validate_diag(free_ip);
    }
}

#[cfg(test)]
mod tests;
