// Synchronization primitives per docs/06§3 + `06§4`. Crate-level home
// for Spinlock, LockClass, IrqGate, PerCpu. RwLock + SeqLock + RCU
// land alongside their first consumers in the dep order from
// `boot-flow.md`.

#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "hosted"))]
extern crate std;

#[cfg(feature = "debug-lockdep")]
pub mod lockdep;
mod percpu;
mod lock_class;
/// The preempt-count gate every spinning lock here takes, so a lock owner
/// cannot be descheduled inside its critical section (Linux `spin_lock` =
/// `preempt_disable` + acquire).
pub mod preempt_gate;
pub use preempt_gate::{set_preempt_ops, PreemptOps};
pub use lock_class::*;
/// The single relax step every spin loop here takes — and the hook that lets a
/// spinning CPU keep servicing cross-CPU work it owes.
pub mod spin_relax;
pub use spin_relax::{relax, set_spin_relax_hook, SpinRelaxFn};
mod rcu;
mod rwlock;
mod seqlock;
/// Serialisation for the tests that install or read the process-global
/// preempt gate; see `test_serial::gate`.
#[cfg(test)]
mod test_serial;
pub use percpu::{
    CacheLine, CpuLocalSource, NoopCpuLocal, PerCpu, CACHELINE_BYTES, MAX_CPUS,
};
pub use seqlock::SeqLock;
pub use rcu::{
    call_rcu, note_qs, pending_callbacks, rcu_barrier, rcu_process_callbacks, set_cpu_hooks,
    rcu_read_lock, set_wait_hooks, synchronize_rcu, wait_epoch, RcuCallback, RcuReadGuard,
};
pub use rwlock::{RwLock, RwReadGuard, RwWriteGuard};

#[cfg(any(test, feature = "hosted"))]
pub use percpu::HostedCpuLocal;

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "debug-smp")]
use core::sync::atomic::AtomicU64;

// ---------------------------------------------------------------------------
// Lock-class taxonomy per `06§3.6`. Variants are zero-sized marker types so
// the class is a compile-time property of every Spinlock<T, C>; no runtime
// overhead. `debug-lockdep` builds (cargo feature, future) will read these
// classes via the `LockClass` trait to enforce the partial order.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// IrqGate — generic gate that enables `lock_irqsave` per `06§3.1`
// without a `dyn` trait. Hosted tests use `NoopIrq`; arch crates supply
// their own gate via HAL `CpuOps` (`14§4`). Generic-only per `07§5`.
// ---------------------------------------------------------------------------

pub trait IrqGate: 'static {
    /// Save current IRQ state, disable IRQs, return opaque flags.
    /// # SAFETY: hardware-state mutation; caller must pair with `restore`.
    /// # C: O(1)
    unsafe fn save_disable() -> u64;
    /// Save current IRQ state, ENABLE IRQs, return opaque flags. Inverse of
    /// `save_disable`: pairs with `restore` to run a bounded section with IRQs
    /// ON inside an IRQ-masked entry, exit, or idle context. Caller must
    /// hold no plain lock that IRQ/softirq context also takes (else deadlock).
    /// # SAFETY: hardware-state mutation; caller must pair with `restore`.
    /// # C: O(1)
    unsafe fn save_enable() -> u64;
    /// Restore IRQ state from `flags`.
    /// # SAFETY: caller pairs this with the matching `save_disable`.
    /// # C: O(1)
    unsafe fn restore(flags: u64);
}

/// Hosted/no-op gate — used in tests and any context with no hardware
/// IRQs to disable. Real arch gates live in `hal-x86_64` / `hal-aarch64`.
pub struct NoopIrq;
impl IrqGate for NoopIrq {
    unsafe fn save_disable() -> u64 { 0 }
    unsafe fn save_enable() -> u64 { 0 }
    unsafe fn restore(_flags: u64) {}
}

// ---------------------------------------------------------------------------
// BhGate — the softirq counterpart of `IrqGate`, enabling `lock_bh`
// (Linux `spin_lock_bh`) per `06§3.1`.
//
// Same shape and the same reason as `IrqGate`: the bottom-half count lives in
// `sched`'s `preempt_count`, which is ABOVE `sync` in the dep order, so `sync`
// cannot call it directly. The gate is a generic parameter the caller supplies,
// monomorphized per `07§5` — no `dyn`.
//
// `spin_lock_bh` is the correct fix for a lock shared between process context
// and a SOFTIRQ (not a hard IRQ): disabling bottom halves on this CPU is
// sufficient and far cheaper than masking interrupts. `lock_irqsave` remains
// the fix when the sharer is a hard-IRQ handler.
// ---------------------------------------------------------------------------

pub trait BhGate: 'static {
    /// Enter `spin_lock_bh` accounting: raise this CPU's BH-disable field and
    /// its spinning-lock preemption credit.
    /// # SAFETY: must pair 1:1 with `enable`; an unbalanced disable pins
    /// `in_interrupt()` true on this CPU and stops it rescheduling.
    /// # C: O(1)
    unsafe fn disable();
    /// Diagnose the pair while the acquisition trace is still live.
    /// Production gates normally use this no-op default. # C: O(1)
    fn check_enable() {}
    /// Leave `spin_lock_bh` accounting and drain anything that became pending
    /// while bottom halves were off.
    /// # SAFETY: must pair a prior `disable`, at a point where a softirq drain
    /// and a reschedule are legal (lock already released).
    /// # C: O(1) + drain
    unsafe fn enable();
}

/// Hosted/no-op gate — no softirq machinery to gate. Real gate lives in
/// `sched` (`SchedBh`), which owns `preempt_count`.
pub struct NoopBh;
impl BhGate for NoopBh {
    unsafe fn disable() {}
    unsafe fn enable() {}
}

// ---------------------------------------------------------------------------
// SMP spin-stall probe (`debug-smp`). Capture-first diagnostic for the -smp
// wake-path hardening: when a `Spinlock::lock()` spins past a threshold it is a
// suspected IF=0 cross-CPU stall, so we report the held lock's CLASS rank via an
// installable hook (the consumer wires it to klog). Entirely compiled out unless
// the `debug-smp` feature is on — prod pays zero. The hook defaults to a no-op,
// so even a `debug-smp` build that never installs one stays silent.
// ---------------------------------------------------------------------------
#[cfg(feature = "debug-smp")]
mod spin_probe {
    use core::sync::atomic::{AtomicPtr, Ordering};

    /// Reported once a `lock()` spins this many iterations without acquiring.
    /// Large enough that only a genuine stall (not normal contention) trips it.
    pub const SPIN_WARN_ITERS: u64 = 200_000_000;

    /// Installed probe sink: `(class rank, lock address, owner tid, spin iters)`.
    pub type SpinWarnFn = fn(u16, usize, u64, u64);
    /// Task identity provider. The sync crate cannot depend on the scheduler,
    /// so the scheduler installs this after its first runqueue is live.
    pub type SpinOwnerFn = fn() -> u64;
    static HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
    static OWNER_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

    /// Install the spin-stall reporter (consumer wires it to klog). # C: O(1)
    pub fn set_spin_warn_hook(f: SpinWarnFn) { HOOK.store(f as *mut (), Ordering::Release); }

    /// Install the current-task identity provider. # C: O(1)
    pub fn set_spin_owner_hook(f: SpinOwnerFn) { OWNER_HOOK.store(f as *mut (), Ordering::Release); }

    /// Current lock owner, or zero before the scheduler has installed its hook.
    /// # C: O(1)
    #[inline]
    pub fn current_owner() -> u64 {
        let p = OWNER_HOOK.load(Ordering::Acquire);
        if p.is_null() { return 0; }
        // SAFETY: OWNER_HOOK is installed only through set_spin_owner_hook
        // with the documented SpinOwnerFn signature and never freed.
        let f: SpinOwnerFn = unsafe { core::mem::transmute(p) };
        f()
    }

    /// Fire the reporter if installed. # C: O(1)
    #[inline]
    pub fn warn(rank: u16, lock: usize, owner: u64, iters: u64) {
        let p = HOOK.load(Ordering::Acquire);
        if p.is_null() { return; }
        // SAFETY: HOOK is only ever set via set_spin_warn_hook with the
        // documented SpinWarnFn signature; non-null implies a live fn pointer.
        let f: SpinWarnFn = unsafe { core::mem::transmute(p) };
        f(rank, lock, owner, iters);
    }
}
#[cfg(feature = "debug-smp")]
pub use spin_probe::{set_spin_owner_hook, set_spin_warn_hook, SpinOwnerFn, SpinWarnFn};

// ---------------------------------------------------------------------------
// Spinlock<T, C> — `06§3.1`.
// ---------------------------------------------------------------------------

pub struct Spinlock<T, C: LockClass> {
    locked: AtomicBool,
    #[cfg(feature = "debug-smp")]
    owner: AtomicU64,
    cell: UnsafeCell<T>,
    _class: PhantomData<C>,
}

// SAFETY: Spinlock mediates exclusive access via the AtomicBool gate;
// only one Guard exists at a time, so T behaves as if &mut-borrowed.
unsafe impl<T: Send, C: LockClass> Sync for Spinlock<T, C> {}
unsafe impl<T: Send, C: LockClass> Send for Spinlock<T, C> {}

impl<T, C: LockClass> Spinlock<T, C> {
    /// # C: O(1)
    pub const fn new(val: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            #[cfg(feature = "debug-smp")]
            owner: AtomicU64::new(0),
            cell: UnsafeCell::new(val),
            _class: PhantomData,
        }
    }

    /// Block until lock acquired. Suitable for non-IRQ-shared contexts.
    /// # C: O(contention)
    /// # Lk: this lock acquired
    #[cfg_attr(feature = "debug-preempt", track_caller)]
    pub fn lock(&self) -> Guard<'_, T, C> {
        // lockdep: a bare acquisition. Recorded BEFORE the spin so a lock that
        // deadlocks here is still attributed — the report is the reason we are
        // spinning. Compiled out entirely unless `debug-lockdep`.
        #[cfg(feature = "debug-lockdep")]
        crate::lockdep::note_acquire(C::rank(), C::name(), false, self as *const _ as usize);
        #[cfg(feature = "debug-smp")]
        let mut iters: u64 = 0;
        // Linux `spin_lock` = `preempt_disable()` then the acquire: the owner
        // of a spinning lock must not be descheduled inside its critical
        // section. Raised BEFORE the spin, as the reference does, so a waiter
        // is not itself preempted into a position where it holds the count
        // without the lock.
        let preempt = crate::preempt_gate::acquire(C::rank());
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            crate::spin_relax::relax();
            // Capture-first SMP probe (prod-inert: compiled out unless `debug-smp`).
            // A lock spin past the threshold is a suspected IF=0 cross-CPU stall —
            // report the lock CLASS rank so the next -smp boot names the vertex.
            #[cfg(feature = "debug-smp")]
            {
                iters += 1;
                if iters == spin_probe::SPIN_WARN_ITERS {
                    spin_probe::warn(C::rank(), self as *const _ as usize,
                        self.owner.load(Ordering::Relaxed), iters);
                }
            }
        }
        #[cfg(feature = "debug-smp")]
        self.owner.store(spin_probe::current_owner(), Ordering::Relaxed);
        Guard { lock: self, preempt }
    }

    /// # C: O(1)
    /// # Lk: this lock acquired on Some
    pub fn try_lock(&self) -> Option<Guard<'_, T, C>> {
        // Preemption goes off before the attempt and back on if it failed —
        // Linux `spin_trylock` (`preempt_disable(); if (!try) preempt_enable();`).
        // Raising it first is what makes the acquire and the count one step:
        // between a successful CAS and a later disable the owner is preemptible
        // while already holding the lock, which is the defect this gate exists
        // to close.
        let preempt = crate::preempt_gate::acquire(C::rank());
        match self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        {
            Ok(_) => {
                #[cfg(feature = "debug-smp")]
                self.owner.store(spin_probe::current_owner(), Ordering::Relaxed);
                Some(Guard { lock: self, preempt })
            }
            Err(_) => { crate::preempt_gate::release(preempt); None }
        }
    }

    /// Release a lock acquired via `lock()` whose `Guard` was
    /// `core::mem::forget`-ed, so the release happens somewhere the guard
    /// cannot reach — the scheduler's rq-lock is held across a context
    /// switch and released by the INCOMING task on a different stack
    /// (Linux `finish_lock_switch`). After this the lock is free; any
    /// `&T`/`&mut T` obtained from the forgotten guard must not be used.
    /// # SAFETY: caller asserts this lock is currently held by exactly one
    /// forgotten guard (the matching `lock()` + `mem::forget`); calling on
    /// an unheld lock, or twice, breaks mutual exclusion (UB on the
    /// protected data). Must pair 1:1 with the forgotten acquisition.
    /// # C: O(1)
    /// # Lk: this lock released
    pub unsafe fn raw_unlock(&self) {
        #[cfg(feature = "debug-smp")]
        self.owner.store(0, Ordering::Relaxed);
        self.locked.store(false, Ordering::Release);
        // The forgotten guard's preempt level is owed by whoever performs the
        // release — here, the incoming task. Every task in a switch takes the
        // rq lock once and performs exactly one `raw_unlock`, so the per-task
        // count balances; omitting this leaks one level per context switch and
        // the CPU stops rescheduling entirely.
        #[cfg(feature = "debug-preempt")]
        crate::preempt_gate::release_forgotten(C::rank());
        #[cfg(not(feature = "debug-preempt"))]
        crate::preempt_gate::release(crate::preempt_gate::installed_release());
    }

    /// IRQ-safe lock per `06§3.1`. Disables IRQs via `IrqGate`, then
    /// spins for the lock. Restores on `Drop`.
    /// # C: O(contention)
    /// # Lk: this lock acquired; IRQs off
    #[cfg_attr(feature = "debug-preempt", track_caller)]
    pub fn lock_irqsave<I: IrqGate>(&self) -> IrqGuard<'_, T, C, I> {
        // lockdep: the correct pattern for an ISR-shared lock; recorded so a
        // class fixed at every site stops being reported.
        #[cfg(feature = "debug-lockdep")]
        crate::lockdep::note_acquire(C::rank(), C::name(), true, self as *const _ as usize);
        // SAFETY: caller pairs disable with restore via IrqGuard::Drop;
        // the matching restore happens in IrqGuard::drop with same flags.
        let flags = unsafe { I::save_disable() };
        // Linux `spin_lock_irqsave` = `local_irq_save` + `preempt_disable` +
        // acquire. Masking interrupts already stops a tick-driven preemption,
        // but not a VOLUNTARY reschedule reached from inside the section, and
        // the guard's `Drop` restores flags before the count comes back — so
        // the count is what covers the window where interrupts are on again.
        let preempt = crate::preempt_gate::acquire(C::rank());
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            crate::spin_relax::relax();
        }
        #[cfg(feature = "debug-smp")]
        self.owner.store(spin_probe::current_owner(), Ordering::Relaxed);
        IrqGuard { lock: self, flags, preempt, _g: PhantomData }
    }

    /// BH-safe lock per `06§3.1` (Linux `spin_lock_bh`). Disables this CPU's
    /// bottom halves via `BhGate`, then spins for the lock; `Drop` releases the
    /// lock FIRST and re-enables bottom halves after, which is what makes the
    /// drain that `local_bh_enable` may run safe — it can take this same lock.
    ///
    /// Use this, not `lock_irqsave`, when the other side is a SOFTIRQ: masking
    /// interrupts to exclude a bottom half is both unnecessary and costly (it
    /// stalls the timer tick, which is the mechanism behind the observed
    /// multi-second I/O stalls — see `skizm.md` 3.0b).
    /// # C: O(contention)
    /// # Lk: this lock acquired; softirqs off on this CPU
    #[cfg_attr(feature = "debug-preempt", track_caller)]
    pub fn lock_bh<B: BhGate>(&self) -> LockBhGuard<'_, T, C, B> {
        // lockdep: BH-disabled is the correct pattern for a softirq-shared
        // lock, so record it as gated — same as irqsave — or a class fixed at
        // every site would keep being reported.
        #[cfg(feature = "debug-lockdep")]
        crate::lockdep::note_acquire(C::rank(), C::name(), true, self as *const _ as usize);
        // SAFETY: paired with B::enable in LockBhGuard::drop, after the release.
        unsafe { B::disable(); }
        // Join the held-lock trace without touching the count: this section
        // is otherwise invisible to every sleep-while-atomic report, which is
        // why one of them names no lock at all.
        let preempt = crate::preempt_gate::acquire_trace_only(C::rank());
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            crate::spin_relax::relax();
        }
        #[cfg(feature = "debug-smp")]
        self.owner.store(spin_probe::current_owner(), Ordering::Relaxed);
        LockBhGuard { lock: self, preempt, _g: PhantomData }
    }
}

pub struct Guard<'a, T, C: LockClass> {
    lock: &'a Spinlock<T, C>,
    /// The release half of the gate this acquisition used, so an installation
    /// that lands mid-section can never produce an unmatched decrement.
    preempt: crate::preempt_gate::PreemptToken,
}

impl<T, C: LockClass> Deref for Guard<'_, T, C> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: Guard exists only after the AtomicBool CAS succeeded;
        // sole accessor for the lifetime of Guard per Spinlock invariant.
        unsafe { &*self.lock.cell.get() }
    }
}

impl<T, C: LockClass> DerefMut for Guard<'_, T, C> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: Guard exists only after the AtomicBool CAS succeeded;
        // sole mutable accessor for the lifetime of Guard per Spinlock invariant.
        unsafe { &mut *self.lock.cell.get() }
    }
}

impl<T, C: LockClass> Drop for Guard<'_, T, C> {
    fn drop(&mut self) {
        // Release, THEN re-enable preemption: a reschedule taken at the next
        // natural point must never find this lock still held.
        #[cfg(feature = "debug-smp")]
        self.lock.owner.store(0, Ordering::Relaxed);
        self.lock.locked.store(false, Ordering::Release);
        crate::preempt_gate::release(self.preempt);
    }
}

pub struct IrqGuard<'a, T, C: LockClass, I: IrqGate> {
    lock: &'a Spinlock<T, C>,
    flags: u64,
    preempt: crate::preempt_gate::PreemptToken,
    _g: PhantomData<I>,
}

impl<T, C: LockClass, I: IrqGate> Deref for IrqGuard<'_, T, C, I> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: IrqGuard exists only after lock CAS + IRQ disable;
        // sole accessor for its lifetime per Spinlock invariant.
        unsafe { &*self.lock.cell.get() }
    }
}

impl<T, C: LockClass, I: IrqGate> DerefMut for IrqGuard<'_, T, C, I> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: IrqGuard holds both lock + IRQ-disable; sole mutable
        // accessor for its lifetime per Spinlock invariant.
        unsafe { &mut *self.lock.cell.get() }
    }
}

impl<T, C: LockClass, I: IrqGate> Drop for IrqGuard<'_, T, C, I> {
    fn drop(&mut self) {
        #[cfg(feature = "debug-smp")]
        self.lock.owner.store(0, Ordering::Relaxed);
        self.lock.locked.store(false, Ordering::Release);
        // SAFETY: paired with the save_disable in lock_irqsave; same flags.
        unsafe { I::restore(self.flags) };
        // After the flag restore, exactly as the reference orders
        // `spin_unlock_irqrestore`.
        crate::preempt_gate::release(self.preempt);
    }
}

/// Guard for `lock_bh` (Linux `spin_unlock_bh` on drop).
pub struct LockBhGuard<'a, T, C: LockClass, B: BhGate> {
    lock: &'a Spinlock<T, C>,
    /// The trace half this acquisition joined, carried so a gate installed
    /// mid-section can never produce an unmatched pop.
    preempt: crate::preempt_gate::PreemptToken,
    _g: PhantomData<B>,
}

impl<T, C: LockClass, B: BhGate> Deref for LockBhGuard<'_, T, C, B> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: LockBhGuard exists only after the lock CAS succeeded; sole accessor for its lifetime per the Spinlock invariant.
        unsafe { &*self.lock.cell.get() }
    }
}

impl<T, C: LockClass, B: BhGate> DerefMut for LockBhGuard<'_, T, C, B> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: LockBhGuard holds the lock plus BH-disable; sole mutable accessor for its lifetime per the Spinlock invariant.
        unsafe { &mut *self.lock.cell.get() }
    }
}

impl<T, C: LockClass, B: BhGate> Drop for LockBhGuard<'_, T, C, B> {
    fn drop(&mut self) {
        // Release BEFORE re-enabling bottom halves. `local_bh_enable` may drain
        // softirqs inline, and a handler in that drain is entitled to take this
        // very lock — that is the whole point of holding it `_bh`. Re-enabling
        // first would deadlock against our own still-held lock.
        #[cfg(feature = "debug-smp")]
        self.lock.owner.store(0, Ordering::Relaxed);
        self.lock.locked.store(false, Ordering::Release);
        B::check_enable();
        crate::preempt_gate::release(self.preempt);
        // SAFETY: pairs the B::disable in lock_bh; the lock is released, so a drain here may take it.
        unsafe { B::enable(); }
    }
}
