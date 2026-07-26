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

use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// Ranks are the class identity (`LockClass::rank`, unique per class by
/// construction). The highest declared rank is 206; round up so a new class
/// cannot silently fall off the end.
pub const MAX_CLASS_RANK: usize = 256;

/// Per-LOCK usage slots. Keyed by the lock's address, not its class.
///
/// The class alone is not an identity here: `TaskList` (rank 100) is used as a
/// catch-all by roughly 180 files, and `KMalloc` (200) by five unrelated locks.
/// Judged per class, "some rank-100 lock ran in hard IRQ" and "some OTHER
/// rank-100 lock was taken plainly in process" combine into a violation report
/// for a pair of locks that never interact. That is what kept `TaskList` and
/// `KMalloc` reporting after every real violation in them had been fixed.
///
/// Linux gives each lock its own `lock_class_key`; keying on the instance
/// address is the same idea without touching 180 call sites. A slot is claimed
/// by the first lock to hash there; a second lock landing on a taken slot is
/// counted as UNTRACKED rather than merged into the first — silently sharing a
/// slot would recreate exactly the conflation this fixes.
const LOCK_SLOTS: usize = 1024;

/// Linux usage bits, narrowed to the IRQ-state question.
const USED_IN_HARDIRQ: u8 = 1 << 0;
const USED_IN_SOFTIRQ: u8 = 1 << 1;
/// Taken with a bare `lock()` while IRQs were enabled (process context).
const USED_PLAIN_PROCESS: u8 = 1 << 2;
/// One report per class; a wedged CPU must not flood the log.
const REPORTED: u8 = 1 << 3;

static USAGE: [AtomicU8; LOCK_SLOTS] = [const { AtomicU8::new(0) }; LOCK_SLOTS];
/// Address owning each slot (0 = unclaimed).
static OWNER: [AtomicUsize; LOCK_SLOTS] = [const { AtomicUsize::new(0) }; LOCK_SLOTS];
/// Rank+name of the owner, for the report.
static OWNER_RANK: [AtomicU16; LOCK_SLOTS] = [const { AtomicU16::new(0) }; LOCK_SLOTS];
/// First hard-IRQ acquisition site, and first plain-process acquisition site.
///
/// The lock address alone says WHICH lock is inconsistent; it does not say
/// where the two conflicting acquisitions are, and with a class shared by ~180
/// locks the class name does not either. Recording one call site per side turns
/// the report into two `addr2line` inputs — the same provenance trick the heap
/// hunt used to name a UAF's freer.
static HARDIRQ_IP: [AtomicU64; LOCK_SLOTS] = [const { AtomicU64::new(0) }; LOCK_SLOTS];
static PROCESS_IP: [AtomicU64; LOCK_SLOTS] = [const { AtomicU64::new(0) }; LOCK_SLOTS];

/// Caller of `Spinlock::lock*`. Same frame-pointer / x30 ABI `kalloc::caller`
/// uses; `0` where unavailable.
#[inline(always)]
fn acquire_ip() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let ip: u64;
        // SAFETY: frame-pointer=always, so RBP is a valid frame base and [rbp+8] is this frame's return address. Read-only.
        unsafe { core::arch::asm!("mov {out}, [rbp+8]", out = out(reg) ip, options(nostack, preserves_flags)); }
        ip
    }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let ip: u64;
        // SAFETY: x30 holds the return address at this inlined first statement. Read-only.
        unsafe { core::arch::asm!("mov {out}, x30", out = out(reg) ip, options(nomem, nostack, preserves_flags)); }
        ip
    }
    #[cfg(not(all(any(target_arch = "x86_64", target_arch = "aarch64"), target_os = "oxide-kernel")))]
    { 0 }
}
/// Acquisitions dropped because their slot was taken by another lock. Non-zero
/// means the table is too small to cover every lock this boot touched.
static UNTRACKED: AtomicU32 = AtomicU32::new(0);

/// Slot for `addr`, claiming it if free. `None` when another lock owns it.
fn slot_for(addr: usize) -> Option<usize> {
    // Locks are at least pointer-aligned and usually far apart; fold the high
    // bits in so nearby statics do not all collide.
    let mut h = addr >> 3;
    h ^= h >> 11;
    let start = h % LOCK_SLOTS;
    let cur = OWNER[start].load(Ordering::Acquire);
    if cur == addr { return Some(start); }
    if cur == 0
        && OWNER[start].compare_exchange(0, addr, Ordering::AcqRel, Ordering::Acquire).is_ok()
    {
        return Some(start);
    }
    if OWNER[start].load(Ordering::Acquire) == addr { return Some(start); }
    UNTRACKED.fetch_add(1, Ordering::Relaxed);
    None
}

/// Acquisitions that could not be tracked because their slot was occupied.
/// # C: O(1)
pub fn untracked() -> u32 { UNTRACKED.load(Ordering::Acquire) }

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
/// Null until installed. While null, lockdep records NOTHING — see
/// `note_acquire`.
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
pub fn note_acquire(rank: u16, name: &'static str, irqsafe: bool, addr: usize) {
    // Record nothing until the IRQ-state hook exists. Before it does, every
    // acquisition would be filed as "plain process" no matter the real state,
    // and early boot is exactly where that is most wrong: `KAlloc::init` runs
    // from `kmain::early::init` — single-CPU, interrupts masked — long before
    // `install_lockdep`, and was reported as the plain-process half of a
    // `KMalloc` violation on every boot for that reason alone.
    //
    // Not recording is right rather than merely convenient: pre-install
    // acquisitions are provably single-threaded with interrupts masked, so
    // there is no violation to miss. Guessing at unobservable state produced a
    // false report that survived several rounds of chasing.
    if IRQ_STATE_HOOK.load(Ordering::Acquire).is_null() { return; }
    let Some(idx) = slot_for(addr) else { return };
    OWNER_RANK[idx].store(rank, Ordering::Relaxed);
    let ip = acquire_ip();
    let bit = match context() {
        Ctx::Hardirq => { let _ = HARDIRQ_IP[idx].compare_exchange(0, ip, Ordering::AcqRel, Ordering::Relaxed); USED_IN_HARDIRQ }
        Ctx::Softirq => USED_IN_SOFTIRQ,
        // An irqsave acquisition in process context is exactly the correct
        // pattern; recording it as "plain" would report every fixed site.
        Ctx::Process if !irqsafe && !irqs_disabled() => { let _ = PROCESS_IP[idx].compare_exchange(0, ip, Ordering::AcqRel, Ordering::Relaxed); USED_PLAIN_PROCESS }
        Ctx::Process => 0,
    };
    if bit == 0 { return; }
    let prev = USAGE[idx].fetch_or(bit, Ordering::AcqRel);
    let now = prev | bit;
    if now & REPORTED != 0 { return; }
    // Two independent violations, both of the same shape — a deferred context
    // spins on a lock its own CPU already holds in process context:
    //
    //   hard IRQ  vs plain process -> the process side needs `lock_irqsave`
    //   softirq   vs plain process -> the process side needs `lock_bh`
    //
    // Linux keeps both (`LOCK_USED_IN_HARDIRQ` / `LOCK_USED_IN_SOFTIRQ` against
    // the matching ENABLED bits). Only the hard-IRQ pair was checked here, so a
    // softirq-shared lock taken plainly in process context — the exact case
    // `spin_lock_bh` exists for — was invisible.
    if now & USED_PLAIN_PROCESS == 0 { return; }
    if now & (USED_IN_HARDIRQ | USED_IN_SOFTIRQ) == 0 { return; }
    if USAGE[idx].fetch_or(REPORTED, Ordering::AcqRel) & REPORTED != 0 { return; }
    report(rank, name, now, addr, HARDIRQ_IP[idx].load(Ordering::Acquire), PROCESS_IP[idx].load(Ordering::Acquire));
}

fn report(rank: u16, name: &'static str, bits: u8, addr: usize, hardirq_ip: u64, process_ip: u64) {
    klog::write_raw(b"[LOCKDEP] inconsistent usage: class=");
    klog::write_raw(name.as_bytes());
    klog::write_raw(b" rank=");
    klog::write_dec_u64(rank as u64);
    // The ADDRESS is what identifies the offending lock: the class is shared by
    // ~180 locks, so the name alone does not say which one.
    klog::write_raw(b" lock=0x");
    klog::write_hex_u64(addr as u64);
    if bits & USED_IN_HARDIRQ != 0 {
        klog::write_raw(b" used-in-hardirq AND taken-plain-in-process");
        if bits & USED_IN_SOFTIRQ != 0 { klog::write_raw(b" (also softirq)"); }
    } else {
        klog::write_raw(b" used-in-SOFTIRQ AND taken-plain-in-process (needs lock_bh)");
    }
    klog::write_raw(b"\n  hardirq-acquire-ip=0x");
    klog::write_hex_u64(hardirq_ip);
    klog::write_raw(b"  plain-process-acquire-ip=0x");
    klog::write_hex_u64(process_ip);
    if bits & USED_IN_HARDIRQ != 0 {
        klog::write_raw(b"\n  -> needs lock_irqsave at every site, or the hard-IRQ side must move (06 3.1)\n");
    } else {
        klog::write_raw(b"\n  -> needs lock_bh on the process side (06 3.1)\n");
    }
}

/// Class-usage snapshot for the boot-time summary and for tests.
/// Returns `(used_in_hardirq, used_in_softirq, used_plain_process, reported)`.
/// # C: O(1)
pub fn usage(addr: usize) -> (bool, bool, bool, bool) {
    let Some(idx) = slot_for(addr) else { return (false, false, false, false) };
    let b = USAGE[idx].load(Ordering::Acquire);
    (b & USED_IN_HARDIRQ != 0, b & USED_IN_SOFTIRQ != 0,
     b & USED_PLAIN_PROCESS != 0, b & REPORTED != 0)
}

/// Clear all recorded usage. Tests only — the kernel never resets this.
/// # C: O(MAX_CLASS_RANK)
pub fn reset_for_tests() {
    for slot in USAGE.iter() { slot.store(0, Ordering::Release); }
    for slot in OWNER.iter() { slot.store(0, Ordering::Release); }
    for slot in HARDIRQ_IP.iter() { slot.store(0, Ordering::Release); }
    for slot in PROCESS_IP.iter() { slot.store(0, Ordering::Release); }
    UNTRACKED.store(0, Ordering::Release);
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

    /// Distinct fake lock addresses. Usage is keyed per LOCK now, so tests that
    /// share a class must not share an address.
    const A: usize = 0x1000;
    const B: usize = 0x2000;
    const C: usize = 0x3000;
    const D: usize = 0x4000;
    const E: usize = 0x5000;
    const F: usize = 0x6000;

    #[test]
    fn plain_process_then_hardirq_is_reported() {
        install();
        reset_for_tests();
        set_ctx(Ctx::Process);
        note_acquire(90, "TestA", false, A);
        assert_eq!(usage(A).3, false, "one context alone is not a violation");
        set_ctx(Ctx::Hardirq);
        note_acquire(90, "TestA", false, A);
        assert!(usage(A).3, "hardirq + plain-process on the SAME lock must report");
    }

    /// The whole point of keying on the instance: two DIFFERENT locks that
    /// merely share a class must not combine into a violation. `TaskList` is
    /// used by ~180 locks, so per-class tracking reported exactly this.
    #[test]
    fn two_locks_sharing_a_class_do_not_combine() {
        install();
        reset_for_tests();
        set_ctx(Ctx::Process);
        note_acquire(100, "TaskList", false, A);
        set_ctx(Ctx::Hardirq);
        note_acquire(100, "TaskList", false, B);
        assert!(!usage(A).3, "lock A alone is only ever process-plain");
        assert!(!usage(B).3, "lock B alone is only ever hardirq");
    }

    #[test]
    fn irqsave_everywhere_is_clean() {
        install();
        reset_for_tests();
        set_ctx(Ctx::Process);
        note_acquire(91, "TestB", true, C);
        set_ctx(Ctx::Hardirq);
        note_acquire(91, "TestB", true, C);
        assert!(!usage(C).3, "irqsave at every site is the correct pattern");
    }

    /// The `spin_lock_bh` case: a softirq-shared lock taken plainly in process
    /// context deadlocks the same CPU just as a hard-IRQ one does, and was not
    /// checked at all before.
    #[test]
    fn softirq_plus_plain_process_is_reported() {
        install();
        reset_for_tests();
        const S: usize = 0x8000;
        set_ctx(Ctx::Process);
        note_acquire(140, "Socket", false, S);
        assert!(!usage(S).3, "process alone is not a violation");
        set_ctx(Ctx::Softirq);
        note_acquire(140, "Socket", false, S);
        assert!(usage(S).3, "softirq + plain-process must report (needs lock_bh)");
    }

    #[test]
    fn softirq_with_bh_protected_process_is_clean() {
        install();
        reset_for_tests();
        const S: usize = 0x9000;
        // `lock_bh` records irqsafe=true, so a BH-protected process acquisition
        // is not "plain" and must not report.
        set_ctx(Ctx::Process);
        note_acquire(141, "SocketBh", true, S);
        set_ctx(Ctx::Softirq);
        note_acquire(141, "SocketBh", false, S);
        assert!(!usage(S).3, "lock_bh on the process side is the correct pattern");
    }

    #[test]
    fn hardirq_only_is_clean() {
        install();
        reset_for_tests();
        set_ctx(Ctx::Hardirq);
        note_acquire(92, "TestC", false, D);
        assert!(!usage(D).3, "a lock only ever taken in hard IRQ cannot deadlock this way");
    }

    #[test]
    fn a_bare_lock_with_irqs_already_masked_is_not_a_violation() {
        install();
        reset_for_tests();
        set_ctx(Ctx::Process);
        set_irqs_disabled(true);
        note_acquire(94, "TestIrqOff", false, E);
        assert!(!usage(E).2, "IRQs masked implies not a plain-process acquisition");
        set_ctx(Ctx::Hardirq);
        note_acquire(94, "TestIrqOff", false, E);
        assert!(!usage(E).3, "hardirq + irq-masked-process is the correct pattern");
        set_irqs_disabled(false);
    }

    #[test]
    fn irqs_enabled_still_reports() {
        install();
        reset_for_tests();
        set_ctx(Ctx::Process);
        set_irqs_disabled(false);
        note_acquire(95, "TestIrqOn", false, F);
        set_ctx(Ctx::Hardirq);
        note_acquire(95, "TestIrqOn", false, F);
        assert!(usage(F).3, "a genuinely plain process acquisition must still be caught");
    }

    #[test]
    fn reported_once_per_lock() {
        install();
        reset_for_tests();
        const G: usize = 0x7000;
        set_ctx(Ctx::Process);
        note_acquire(93, "TestD", false, G);
        set_ctx(Ctx::Hardirq);
        note_acquire(93, "TestD", false, G);
        assert!(usage(G).3);
        note_acquire(93, "TestD", false, G);
        assert!(usage(G).3);
    }
}
