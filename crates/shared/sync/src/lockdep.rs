//! lockdep — IRQ-state subset of Linux `CONFIG_PROVE_LOCKING` (`06§3.1`).
//!
//! Linux records, at every lock acquisition, which context it happened in, and
//! keeps per-class usage bits (`LOCK_USED_IN_HARDIRQ`, `LOCK_ENABLED_HARDIRQ`,
//! …). A class ever taken in hard-IRQ context *and* taken elsewhere with IRQs
//! enabled is reported as an `inconsistent {HARDIRQ-ON-W} -> {IN-HARDIRQ-W}`
//! usage violation. That is precisely the `06§3.1` rule: a hard-IRQ handler
//! must never spin on a plain lock a process-context holder owns, because the
//! tick preempts the holder and that CPU can never make progress again.
//!
//! Why this is a runtime check and not a build-time one: `Spinlock::lock` is
//! `#[inline]` and is fully inlined at every call site — the aarch64 kernel ELF
//! contains ZERO `bl` to any lock symbol across 50,602 call sites, so no
//! call-graph analysis of the binary can see an acquisition. Source-level
//! analysis has the same problem plus generics and fn-pointer edges. Linux
//! reached the same conclusion; lockdep has always been runtime.
//!
//! Scope: usage bits only. This does NOT implement lock-ordering or
//! deadlock-cycle detection (Linux's `check_prev_add` / dependency graph).
//! Ordering is already covered separately by `LockClass::rank` per `06§3.6`.

use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

/// Ranks are the class identity (`LockClass::rank`, unique per class by
/// construction). The highest declared rank is 206; round up so a new class
/// cannot silently fall off the end.
pub const MAX_CLASS_RANK: usize = 256;

/// Linux usage bits, narrowed to the IRQ-state question.
const USED_IN_HARDIRQ: u8 = 1 << 0;
const USED_IN_SOFTIRQ: u8 = 1 << 1;
/// Taken with a bare `lock()` while IRQs were enabled (process context).
const USED_PLAIN_PROCESS: u8 = 1 << 2;
/// One report per class; a wedged CPU must not flood the log.
const REPORTED: u8 = 1 << 3;

static USAGE: [AtomicU8; MAX_CLASS_RANK] = [const { AtomicU8::new(0) }; MAX_CLASS_RANK];

/// Execution context of an acquisition, as the scheduler sees it.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum Ctx {
    Process = 0,
    Softirq = 1,
    Hardirq = 2,
}

impl Ctx {
    fn from_raw(v: u8) -> Ctx {
        match v { 2 => Ctx::Hardirq, 1 => Ctx::Softirq, _ => Ctx::Process }
    }
}

/// `sync` is a leaf crate — it cannot depend on `sched`, which owns
/// `preempt_count`. The scheduler installs this at boot, exactly like the other
/// cross-layer hooks in this tree. Null until then, which reports `Process`;
/// pre-boot acquisitions are single-threaded with IRQs masked, so that is
/// correct rather than merely convenient.
static CTX_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Reports whether interrupts are ACTUALLY masked on this CPU right now.
///
/// Linux's lockdep asks the hardware (`raw_irqs_disabled()`); it does not infer
/// IRQ state from which lock function was called. That difference matters here:
/// a caller may have masked interrupts by some other means and then taken a
/// bare `lock()`, which is a correct pattern that a method-name-based model
/// misreports as a violation.
///
/// The concrete case is the allocator. `kalloc` disables IRQs itself around the
/// whole alloc/dealloc op (its own `irq_off()` gate, installed at boot in
/// `kmain::early`) and then takes the hole-list lock with a plain `lock()`,
/// exactly because an ISR must not spin on a mainline-held hole list. Judged by
/// method name that reads as "plain in process context", so `KMalloc` was
/// reported as inconsistent on every boot despite being correct.
///
/// Null until installed, which reports "not disabled" — the conservative
/// direction, since it can only over-report, never hide a real violation.
static IRQ_STATE_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the context reporter. Boot path, once, before secondary CPUs start.
/// # SAFETY: `f` must be a `'static` fn returning a valid `Ctx` discriminant.
/// # C: O(1)
pub unsafe fn set_context_hook(f: fn() -> u8) {
    CTX_HOOK.store(f as *mut (), Ordering::Release);
}

/// Install the actual-IRQ-state reporter. Boot path, once.
/// # SAFETY: `f` must be a `'static` fn safe to call from any context,
/// including hard IRQ, and must not allocate or take a lock.
/// # C: O(1)
pub unsafe fn set_irq_state_hook(f: fn() -> bool) {
    IRQ_STATE_HOOK.store(f as *mut (), Ordering::Release);
}

/// True iff interrupts are masked on this CPU right now.
fn irqs_disabled() -> bool {
    let p = IRQ_STATE_HOOK.load(Ordering::Acquire);
    if p.is_null() { return false; }
    // SAFETY: non-null only after `set_irq_state_hook` stored a `fn() -> bool`.
    let f: fn() -> bool = unsafe { core::mem::transmute(p) };
    f()
}

fn context() -> Ctx {
    let p = CTX_HOOK.load(Ordering::Acquire);
    if p.is_null() { return Ctx::Process; }
    // SAFETY: non-null only after `set_context_hook` stored a `fn() -> u8`.
    let f: fn() -> u8 = unsafe { core::mem::transmute(p) };
    Ctx::from_raw(f())
}

/// Record an acquisition and report the first inconsistency per class.
///
/// `irqsafe` distinguishes `lock_irqsave` / `lock_bh` (which make the
/// acquisition legal in any context) from a bare `lock()`. Only bare
/// acquisitions in process context can conflict with hard-IRQ use — that is the
/// whole rule.
///
/// A bare `lock()` taken while interrupts are ALREADY masked is equally safe,
/// so the live hardware state counts as gated too. Linux's lockdep asks the
/// same question of the hardware rather than of the call site.
///
/// # C: O(1) — two atomics on the hot path, no allocation, no locking
pub fn note_acquire(rank: u16, name: &'static str, irqsafe: bool) {
    let idx = rank as usize;
    if idx >= MAX_CLASS_RANK { return; }
    let bit = match context() {
        Ctx::Hardirq => USED_IN_HARDIRQ,
        Ctx::Softirq => USED_IN_SOFTIRQ,
        // An irqsave acquisition in process context is exactly the correct
        // pattern; recording it as "plain" would report every fixed site.
        Ctx::Process if !irqsafe && !irqs_disabled() => USED_PLAIN_PROCESS,
        Ctx::Process => 0,
    };
    if bit == 0 { return; }
    let prev = USAGE[idx].fetch_or(bit, Ordering::AcqRel);
    let now = prev | bit;
    if now & REPORTED != 0 { return; }
    if now & USED_IN_HARDIRQ == 0 || now & USED_PLAIN_PROCESS == 0 { return; }
    if USAGE[idx].fetch_or(REPORTED, Ordering::AcqRel) & REPORTED != 0 { return; }
    report(rank, name, now);
}

fn report(rank: u16, name: &'static str, bits: u8) {
    klog::write_raw(b"[LOCKDEP] inconsistent usage: class=");
    klog::write_raw(name.as_bytes());
    klog::write_raw(b" rank=");
    klog::write_dec_u64(rank as u64);
    klog::write_raw(b" used-in-hardirq AND taken-plain-in-process");
    if bits & USED_IN_SOFTIRQ != 0 { klog::write_raw(b" (also softirq)"); }
    klog::write_raw(b" -> needs lock_irqsave at every site, or the hard-IRQ side must move (06 3.1)\n");
}

/// Class-usage snapshot for the boot-time summary and for tests.
/// Returns `(used_in_hardirq, used_in_softirq, used_plain_process, reported)`.
/// # C: O(1)
pub fn usage(rank: u16) -> (bool, bool, bool, bool) {
    let idx = rank as usize;
    if idx >= MAX_CLASS_RANK { return (false, false, false, false); }
    let b = USAGE[idx].load(Ordering::Acquire);
    (b & USED_IN_HARDIRQ != 0, b & USED_IN_SOFTIRQ != 0,
     b & USED_PLAIN_PROCESS != 0, b & REPORTED != 0)
}

/// Clear all recorded usage. Tests only — the kernel never resets this.
/// # C: O(MAX_CLASS_RANK)
pub fn reset_for_tests() {
    for slot in USAGE.iter() { slot.store(0, Ordering::Release); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU8;

    static TEST_CTX: AtomicU8 = AtomicU8::new(0);
    fn hook() -> u8 { TEST_CTX.load(Ordering::Acquire) }
    fn set_ctx(c: Ctx) { TEST_CTX.store(c as u8, Ordering::Release); }

    static TEST_IRQ_OFF: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);
    fn irq_hook() -> bool { TEST_IRQ_OFF.load(Ordering::Acquire) }
    fn set_irqs_disabled(v: bool) { TEST_IRQ_OFF.store(v, Ordering::Release); }

    fn install() {
        // SAFETY: `hook` is a 'static fn with the documented ABI.
        unsafe { set_context_hook(hook); }
        // SAFETY: `irq_hook` is a 'static fn that only reads an atomic.
        unsafe { set_irq_state_hook(irq_hook); }
        set_irqs_disabled(false);
    }

    #[test]
    fn plain_process_then_hardirq_is_reported() {
        install();
        reset_for_tests();
        set_ctx(Ctx::Process);
        note_acquire(90, "TestA", false);
        assert_eq!(usage(90).3, false, "one context alone is not a violation");
        set_ctx(Ctx::Hardirq);
        note_acquire(90, "TestA", false);
        assert!(usage(90).3, "hardirq + plain-process must report");
    }

    #[test]
    fn irqsave_everywhere_is_clean() {
        install();
        reset_for_tests();
        set_ctx(Ctx::Process);
        note_acquire(91, "TestB", true);
        set_ctx(Ctx::Hardirq);
        note_acquire(91, "TestB", true);
        assert!(!usage(91).3, "irqsave at every site is the correct pattern");
    }

    #[test]
    fn hardirq_only_is_clean() {
        install();
        reset_for_tests();
        set_ctx(Ctx::Hardirq);
        note_acquire(92, "TestC", false);
        assert!(!usage(92).3, "a lock only ever taken in hard IRQ cannot deadlock this way");
    }

    #[test]
    fn a_bare_lock_with_irqs_already_masked_is_not_a_violation() {
        // The allocator's pattern: mask IRQs by another means, then take a
        // plain `lock()`. Judged by method name alone this reads as
        // "plain in process context" and false-reports; judged by the actual
        // IRQ state, as Linux does, it is correct and must stay silent.
        install();
        reset_for_tests();
        set_ctx(Ctx::Process);
        set_irqs_disabled(true);
        note_acquire(94, "TestIrqOff", false);
        assert!(!usage(94).2, "IRQs masked ⇒ not a plain-process acquisition");
        set_ctx(Ctx::Hardirq);
        note_acquire(94, "TestIrqOff", false);
        assert!(!usage(94).3, "hardirq + irq-masked-process is the correct pattern");
    }

    #[test]
    fn irqs_enabled_still_reports() {
        // The same class, taken plain with IRQs actually ENABLED, must still
        // report — the hook must not blanket-suppress.
        install();
        reset_for_tests();
        set_ctx(Ctx::Process);
        set_irqs_disabled(false);
        note_acquire(95, "TestIrqOn", false);
        set_ctx(Ctx::Hardirq);
        note_acquire(95, "TestIrqOn", false);
        assert!(usage(95).3, "a genuinely plain process acquisition must still be caught");
    }

    #[test]
    fn reported_once_per_class() {
        install();
        reset_for_tests();
        set_ctx(Ctx::Process);
        note_acquire(93, "TestD", false);
        set_ctx(Ctx::Hardirq);
        note_acquire(93, "TestD", false);
        assert!(usage(93).3);
        // Second violation on the same class must not re-report.
        note_acquire(93, "TestD", false);
        assert!(usage(93).3);
    }
}
