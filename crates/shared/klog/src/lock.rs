// Console output serialisation — Linux `console_lock`/`console_owner`.
//
// Without this, two CPUs inside `emit_bytes` interleave at arbitrary BYTE
// boundaries: the shared `LINE_START` flag and the sink calls race, so a
// timestamp from one CPU splices into the middle of another CPU's token. That
// is not cosmetic — it corrupts the log we draw conclusions from (a boot
// capture once reported 41,102s of "silence" inside a 295s boot purely from
// spliced timestamps), and it is a real divergence: Linux serialises every
// printk->console fan-out under `console_lock`, and each UART console write
// additionally takes `port->lock`.
//
// klog has NO dependencies (`sync` depends on klog, so using `sync::Spinlock`
// here would be a cycle), so this is a self-contained owner spinlock over
// core atomics — which is also what Linux does for `console_owner`, and for
// the same reason: printk must control its own reentrancy rather than inherit
// a general lock's deadlock rules.
//
// Two deliberate properties, both chosen so the console can never wedge the
// machine — a lock that deadlocks the log is worse than a spliced log:
//   * Same-CPU reentrancy (an IRQ that klogs while that CPU is mid-emit) is
//     detected by owner identity and proceeds WITHOUT blocking. Such nesting
//     can still interleave, exactly as Linux's `console_owner` handover can,
//     but it cannot deadlock.
//   * Acquisition is bounded. A CPU that dies or panics holding the lock would
//     otherwise silence the console permanently, so after `MAX_SPINS` we steal
//     it and write anyway. Linux takes the same escape in
//     `console_flush_on_panic`, which ignores the lock outright.

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

/// Sentinel: lock is free.
const NO_OWNER: u32 = u32::MAX;
/// Sentinel: no cpu-id thunk installed yet (early boot, still UP).
const UNKNOWN_CPU: u32 = u32::MAX - 1;
/// Bounded acquisition, so a dead lock-holder cannot silence the console.
/// Sized to dwarf a UART line write (poll-waiting on THRE) without being an
/// unbounded wait.
const MAX_SPINS: u32 = 40_000_000;

static OWNER: AtomicU32 = AtomicU32::new(NO_OWNER);
static CPU_FN: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Thunk returning the current CPU index, installed once the per-CPU base is
/// live. Same pattern as the clock thunk.
pub type CpuFn = fn() -> u32;

/// Install the cpu-id thunk. Before this, every CPU reports `UNKNOWN_CPU` and
/// the reentrancy shortcut stays off (correct: pre-install we are still UP).
/// # C: O(1)
pub fn set_cpu_fn(f: CpuFn) {
    CPU_FN.store(f as *mut (), Ordering::Release);
}

/// Detach the cpu-id thunk (teardown paths that unwind per-CPU state).
/// # C: O(1)
pub fn clear_cpu_fn() {
    CPU_FN.store(core::ptr::null_mut(), Ordering::Release);
}

/// # C: O(1)
fn cpu_id() -> u32 {
    let raw = CPU_FN.load(Ordering::Acquire);
    if raw.is_null() { return UNKNOWN_CPU; }
    // SAFETY: CPU_FN is only ever populated by set_cpu_fn, which stores a
    // valid CpuFn fn-pointer cast through `as *mut ()`; the reverse transmute
    // restores the identical signature. CpuFn carries no unsafe contract.
    let f: CpuFn = unsafe { core::mem::transmute::<*mut (), CpuFn>(raw) };
    f()
}

/// Held-token for `release`. `false` means "we did not take the lock, do not
/// release it" — either same-CPU reentrancy or a bounded-spin steal.
pub(crate) struct Held(bool);

/// Acquire console ownership, bounded. Never blocks indefinitely and never
/// deadlocks against itself.
/// # C: O(MAX_SPINS) worst case, O(1) uncontended
pub(crate) fn acquire() -> Held {
    let me = cpu_id();
    // Same-CPU nesting: proceed without blocking (see module header).
    if me != UNKNOWN_CPU && OWNER.load(Ordering::Acquire) == me { return Held(false); }
    let mut spins: u32 = 0;
    loop {
        if OWNER.compare_exchange_weak(NO_OWNER, me, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return Held(true);
        }
        spins += 1;
        if spins >= MAX_SPINS {
            // Presumed-dead holder: write unserialised rather than go silent.
            return Held(false);
        }
        core::hint::spin_loop();
    }
}

/// Release console ownership if this call actually took it.
/// # C: O(1)
pub(crate) fn release(h: Held) {
    if h.0 { OWNER.store(NO_OWNER, Ordering::Release); }
}
