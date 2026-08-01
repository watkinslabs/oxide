// `debug-hw-watchpoint`: arm/disarm a hardware write-watchpoint on the most
// recently freed block. kalloc has no HAL/debug-register dependency, so the
// DR0/DR1 arming lives kernel-side and is wired in through these hooks
// (mirrors the corruption-probe hook pattern).

use core::sync::atomic::{AtomicU64, Ordering};

/// Callback signature for `set_watchpoint_hook` (`debug-hw-watchpoint`):
/// arm a hardware write-watchpoint on the just-freed HoleHdr-sized block at
/// byte `addr`. kalloc has no HAL/debug-register dependency, so the actual
/// DR0/DR1 arming lives kernel-side (`pmm::boot::watchpoint_arm`) and is
/// wired in through this hook, mirroring `CorruptionProbeFn`.
pub type WatchpointArmFn = fn(addr: u64);
const WATCHPOINT_HOOK_NONE: u64 = 0;
static WATCHPOINT_HOOK: AtomicU64 = AtomicU64::new(WATCHPOINT_HOOK_NONE);

/// Register the free-block watchpoint hook (`debug-hw-watchpoint`).
/// Idempotent: a later call replaces the prior hook. # C: O(1)
pub fn set_watchpoint_hook(f: WatchpointArmFn) {
    WATCHPOINT_HOOK.store((f as usize) as u64, Ordering::Release);
}

/// Address currently covered by the armed watchpoint, or 0 if none. Lets
/// `alloc()`'s success path tell "this exact block was just legitimately
/// carved back out" (expected, disarm and stay quiet) from "something else
/// wrote to a block kalloc still considers free" (the actual signal).
static WATCHPOINT_ARMED_ADDR: AtomicU64 = AtomicU64::new(0);

/// Callback signature for `set_watchpoint_disarm_hook`: clear the armed
/// hardware watchpoint (DR7 local-enable bits off). No address needed —
/// there is only ever one armed watchpoint (v1 single-block scope).
pub type WatchpointDisarmFn = fn();
static WATCHPOINT_DISARM_HOOK: AtomicU64 = AtomicU64::new(WATCHPOINT_HOOK_NONE);

/// Register the watchpoint-disarm hook (`debug-hw-watchpoint`).
/// # C: O(1)
pub fn set_watchpoint_disarm_hook(f: WatchpointDisarmFn) {
    WATCHPOINT_DISARM_HOOK.store((f as usize) as u64, Ordering::Release);
}

/// Arm the watchpoint hook on a just-freed block, if one is installed.
/// # C: O(1) + hook cost
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
pub(crate) fn disarm_watchpoint_now() {
    if WATCHPOINT_ARMED_ADDR.swap(0, Ordering::AcqRel) == 0 { return; }
    let raw = WATCHPOINT_DISARM_HOOK.load(Ordering::Acquire);
    if raw == WATCHPOINT_HOOK_NONE { return; }
    // SAFETY: only ever stored by `set_watchpoint_disarm_hook` from a
    // `WatchpointDisarmFn`; the round-trip cast restores the fn-pointer's ABI.
    let f: WatchpointDisarmFn = unsafe { core::mem::transmute(raw as usize) };
    f();
}
