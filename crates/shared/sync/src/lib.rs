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
mod rcu;
mod rwlock;
mod seqlock;
pub use percpu::{
    CacheLine, CpuLocalSource, NoopCpuLocal, PerCpu, CACHELINE_BYTES, MAX_CPUS,
};
pub use seqlock::SeqLock;
pub use rcu::{
    call_rcu, note_qs, pending_callbacks, rcu_barrier, rcu_process_callbacks, set_cpu_hooks,
    synchronize_rcu, RcuCallback,
};
pub use rwlock::{RwLock, RwReadGuard, RwWriteGuard};

#[cfg(any(test, feature = "hosted"))]
pub use percpu::HostedCpuLocal;

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Lock-class taxonomy per `06§3.6`. Variants are zero-sized marker types so
// the class is a compile-time property of every Spinlock<T, C>; no runtime
// overhead. `debug-lockdep` builds (cargo feature, future) will read these
// classes via the `LockClass` trait to enforce the partial order.
// ---------------------------------------------------------------------------

pub trait LockClass: 'static {
    /// Rank in the partial order; lower acquired first. Per `06§3.6`.
    /// # C: O(1)
    fn rank() -> u16;
    /// Class name for lockdep reports. `decl_lock_class!` supplies the real
    /// one; hand-written impls inherit this default rather than being forced to
    /// change, since `rank` alone already identifies the class uniquely.
    /// # C: O(1)
    fn name() -> &'static str { "<unnamed>" }
}

macro_rules! decl_lock_class {
    ($($name:ident = $rank:literal),+ $(,)?) => {
        $(
            pub struct $name;
            impl LockClass for $name {
                fn rank() -> u16 { $rank }
                fn name() -> &'static str { stringify!($name) }
            }
        )+
    };
}

decl_lock_class! {
    Buddy        =  0,
    Timer        =  5,
    Slab         = 10,
    Reclaim      = 15,
    PageTable    = 20,
    AnonVma      = 25,
    // Per-page migration-token state.  Kept above i_mmap/rmap (25) and
    // below the address-space VMA tree (30); pageout never holds it while
    // taking a page-table lock or while sleeping.
    Migration    = 26,
    AddressSpace = 30,
    Inode        = 40,
    Dentry       = 50,
    // Pseudo-fs (kernfs) directory-structure locks: held during VFS lookup/
    // readdir (under `Dentry`/`Inode`) and call `SuperBlock::iget` (the icache
    // lock at `Superblock`) to materialise child inodes. Ranked strictly
    // between `Dentry` (50) and `Superblock` (60) so a kernfs node lock may be
    // held WHILE acquiring the SB icache lock (ascending) — the rank window
    // that lets kernfs/procfs/sysfs/devfs route inode builds through `iget`.
    Kernfs       = 55,
    // [D28a] Mount-tree writer serialization (`vfs::mount::MOUNT_WRITE`): the
    // coarse outer lock every mount-tree MUTATOR takes around its multi-structure
    // mutation (MOUNTS + MOUNT_HASH + MOUNTPOINTS + NAMESPACES) so two concurrent
    // writers cannot interleave and leave those structures mutually inconsistent.
    // Ranked ABOVE `Dentry` (50) so the `d_invalidate`→`detach_mounts` path can
    // take it while holding a dentry lock, and BELOW `Superblock` (60) /
    // `MountTable` (70) — the mount-structure locks it is held ACROSS (strict
    // outermost-of-the-mount-locks). NEVER held across a sleeping descend
    // (`namei`/`inode.lookup`) or `put_super`; those run outside the region.
    MountWrite   = 58,
    // ext4 block/inode allocator bitmap serialization (Linux `ext4_lock_group`):
    // held across a group bitmap read-modify-write (read → find-free-bit → set →
    // write) so two concurrent allocations cannot pick the SAME free bit and
    // double-allocate one inode/block. Ranked just BELOW `Superblock` (60) — the
    // allocator takes the SB/state lock (60) for the GDT/counter update WHILE
    // holding this, so ascending order is `Ext4Alloc` (59) → `Superblock` (60).
    Ext4Alloc    = 59,
    Superblock   = 60,
    Modules      = 65,
    MountTable   = 70,
    Namespace    = 75,
    FdTable      = 80,
    SignalQueue  = 90,
    TaskList     = 100,
    Runqueue     = 110,
    Tty          = 120,
    SocketTable  = 130,
    Devices      = 135,
    Socket       = 140,
    // Heap allocator leaf — independent of PMM/Slab, any subsystem may
    // call `KAlloc` with its own lock held; kalloc never calls back into
    // the kernel, so it's the final acquire in any chain.
    KMalloc      = 200,
    // debug-efence arena leaf (C213): consulted from inside `KAlloc::alloc`/
    // `dealloc` BEFORE the holes lock, so it may be taken while any caller
    // lock (≤200) is held. Its hot path takes NO nested tracked lock — all
    // frames are pre-mapped at init, and the RO/RW flip is a lock-free
    // same-PA permission rewrite on the shared kernel tables — so a leaf
    // rank above KMalloc is sound. Debug-only; never in a shipped build.
    Efence       = 205,
    // Guard-paged kernel-stack allocator slot free-list (C213). Held ONLY to
    // pick/return a slot index; frame alloc + page mapping happen OUTSIDE it
    // (like KMalloc releasing before the grow hook), so it takes no nested
    // tracked lock. Leaf rank above the task-creation locks (Runqueue/TaskList)
    // it is acquired under during spawn.
    KStack       = 206,
}

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
    /// ON inside an IF=0 context (Linux `local_irq_enable` while a syscall/fault
    /// waits on slow I/O, so the timer tick + wakeups keep firing). Caller must
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
    /// Linux `local_bh_disable` — raise this CPU's softirq count so softirqs
    /// cannot run here.
    /// # SAFETY: must pair 1:1 with `enable`; an unbalanced disable pins
    /// `in_interrupt()` true on this CPU and stops it rescheduling.
    /// # C: O(1)
    unsafe fn disable();
    /// Linux `local_bh_enable` — drop the count and drain anything that became
    /// pending while bottom halves were off.
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

    /// Installed probe sink: `(lock_class_rank, spin_iters)`.
    pub type SpinWarnFn = fn(u16, u64);
    static HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

    /// Install the spin-stall reporter (consumer wires it to klog). # C: O(1)
    pub fn set_spin_warn_hook(f: SpinWarnFn) { HOOK.store(f as *mut (), Ordering::Release); }

    /// Fire the reporter if installed. # C: O(1)
    #[inline]
    pub fn warn(rank: u16, iters: u64) {
        let p = HOOK.load(Ordering::Acquire);
        if p.is_null() { return; }
        // SAFETY: HOOK is only ever set via set_spin_warn_hook with the
        // documented SpinWarnFn signature; non-null implies a live fn pointer.
        let f: SpinWarnFn = unsafe { core::mem::transmute(p) };
        f(rank, iters);
    }
}
#[cfg(feature = "debug-smp")]
pub use spin_probe::{set_spin_warn_hook, SpinWarnFn};

// ---------------------------------------------------------------------------
// Spinlock<T, C> — `06§3.1`.
// ---------------------------------------------------------------------------

pub struct Spinlock<T, C: LockClass> {
    locked: AtomicBool,
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
            cell: UnsafeCell::new(val),
            _class: PhantomData,
        }
    }

    /// Block until lock acquired. Suitable for non-IRQ-shared contexts.
    /// # C: O(contention)
    /// # Lk: this lock acquired
    pub fn lock(&self) -> Guard<'_, T, C> {
        // lockdep: a bare acquisition. Recorded BEFORE the spin so a lock that
        // deadlocks here is still attributed — the report is the reason we are
        // spinning. Compiled out entirely unless `debug-lockdep`.
        #[cfg(feature = "debug-lockdep")]
        crate::lockdep::note_acquire(C::rank(), C::name(), false);
        #[cfg(feature = "debug-smp")]
        let mut iters: u64 = 0;
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
            // Capture-first SMP probe (prod-inert: compiled out unless `debug-smp`).
            // A lock spin past the threshold is a suspected IF=0 cross-CPU stall —
            // report the lock CLASS rank so the next -smp boot names the vertex.
            #[cfg(feature = "debug-smp")]
            {
                iters += 1;
                if iters == spin_probe::SPIN_WARN_ITERS { spin_probe::warn(C::rank(), iters); }
            }
        }
        Guard { lock: self }
    }

    /// # C: O(1)
    /// # Lk: this lock acquired on Some
    pub fn try_lock(&self) -> Option<Guard<'_, T, C>> {
        match self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        {
            Ok(_) => Some(Guard { lock: self }),
            Err(_) => None,
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
        self.locked.store(false, Ordering::Release);
    }

    /// IRQ-safe lock per `06§3.1`. Disables IRQs via `IrqGate`, then
    /// spins for the lock. Restores on `Drop`.
    /// # C: O(contention)
    /// # Lk: this lock acquired; IRQs off
    pub fn lock_irqsave<I: IrqGate>(&self) -> IrqGuard<'_, T, C, I> {
        // lockdep: the correct pattern for an ISR-shared lock; recorded so a
        // class fixed at every site stops being reported.
        #[cfg(feature = "debug-lockdep")]
        crate::lockdep::note_acquire(C::rank(), C::name(), true);
        // SAFETY: caller pairs disable with restore via IrqGuard::Drop;
        // the matching restore happens in IrqGuard::drop with same flags.
        let flags = unsafe { I::save_disable() };
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        IrqGuard { lock: self, flags, _g: PhantomData }
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
    pub fn lock_bh<B: BhGate>(&self) -> LockBhGuard<'_, T, C, B> {
        // lockdep: BH-disabled is the correct pattern for a softirq-shared
        // lock, so record it as gated — same as irqsave — or a class fixed at
        // every site would keep being reported.
        #[cfg(feature = "debug-lockdep")]
        crate::lockdep::note_acquire(C::rank(), C::name(), true);
        // SAFETY: paired with B::enable in LockBhGuard::drop, after the release.
        unsafe { B::disable(); }
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        LockBhGuard { lock: self, _g: PhantomData }
    }
}

pub struct Guard<'a, T, C: LockClass> {
    lock: &'a Spinlock<T, C>,
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
        self.lock.locked.store(false, Ordering::Release);
    }
}

pub struct IrqGuard<'a, T, C: LockClass, I: IrqGate> {
    lock: &'a Spinlock<T, C>,
    flags: u64,
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
        self.lock.locked.store(false, Ordering::Release);
        // SAFETY: paired with the save_disable in lock_irqsave; same flags.
        unsafe { I::restore(self.flags) };
    }
}

/// Guard for `lock_bh` (Linux `spin_unlock_bh` on drop).
pub struct LockBhGuard<'a, T, C: LockClass, B: BhGate> {
    lock: &'a Spinlock<T, C>,
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
        self.lock.locked.store(false, Ordering::Release);
        // SAFETY: pairs the B::disable in lock_bh; the lock is released, so a drain here may take it.
        unsafe { B::enable(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `BhGate` that counts disable/enable and reports whether bottom halves
    /// are currently off — enough to pin the ordering contract without the
    /// scheduler's real `preempt_count`.
    struct CountingBh;
    static BH_DEPTH: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
    /// Set by the fake "softirq" if it ever observes bottom halves enabled
    /// while the lock is still held — the exact bug `lock_bh` must prevent.
    static BH_REENTERED_HELD: AtomicBool = AtomicBool::new(false);

    impl BhGate for CountingBh {
        unsafe fn disable() { BH_DEPTH.fetch_add(1, Ordering::AcqRel); }
        unsafe fn enable()  { BH_DEPTH.fetch_sub(1, Ordering::AcqRel); }
    }

    fn bh_disabled() -> bool { BH_DEPTH.load(Ordering::Acquire) > 0 }

    #[test]
    fn lock_bh_excludes_softirqs_for_the_whole_critical_section() {
        BH_DEPTH.store(0, Ordering::Release);
        BH_REENTERED_HELD.store(false, Ordering::Release);
        let s: Spinlock<u32, Buddy> = Spinlock::new(0);
        assert!(!bh_disabled());
        {
            let mut g = s.lock_bh::<CountingBh>();
            // The whole critical section runs with bottom halves off; a softirq
            // that took this lock plainly could not run here.
            assert!(bh_disabled(), "spin_lock_bh must hold BH off across the section");
            *g = 7;
            assert!(bh_disabled());
        }
        // Balanced on drop, and re-enabled only after release.
        assert!(!bh_disabled(), "spin_unlock_bh must re-enable bottom halves");
        assert!(!BH_REENTERED_HELD.load(Ordering::Acquire));
        assert_eq!(*s.lock(), 7);
    }

    #[test]
    fn lock_bh_releases_before_reenabling_so_a_drain_can_take_the_lock() {
        // `local_bh_enable` drains inline, and a handler in that drain may take
        // the same lock. Model it: the gate's `enable` tries the lock and must
        // succeed, proving the release already happened.
        static TAKEN_IN_DRAIN: AtomicBool = AtomicBool::new(false);
        static LK: Spinlock<u32, Buddy> = Spinlock::new(0);
        struct DrainingBh;
        impl BhGate for DrainingBh {
            unsafe fn disable() {}
            unsafe fn enable() {
                // Stands in for a softirq handler run by the inline drain.
                TAKEN_IN_DRAIN.store(LK.try_lock().is_some(), Ordering::Release);
            }
        }
        {
            let mut g = LK.lock_bh::<DrainingBh>();
            *g = 1;
        }
        assert!(
            TAKEN_IN_DRAIN.load(Ordering::Acquire),
            "lock must be released before local_bh_enable drains, or the drain self-deadlocks"
        );
    }

    #[test]
    fn noop_bh_gate_is_inert() {
        let s: Spinlock<u32, Buddy> = Spinlock::new(3);
        {
            let mut g = s.lock_bh::<NoopBh>();
            *g += 1;
        }
        assert_eq!(*s.lock(), 4);
    }

    #[test]
    fn lock_round_trip() {
        let s: Spinlock<u32, Buddy> = Spinlock::new(0);
        {
            let mut g = s.lock();
            *g = 42;
        }
        assert_eq!(*s.lock(), 42);
    }

    #[test]
    fn try_lock_fails_when_held() {
        let s: Spinlock<u32, Buddy> = Spinlock::new(7);
        let g = s.lock();
        assert!(s.try_lock().is_none());
        drop(g);
        assert!(s.try_lock().is_some());
    }

    #[test]
    fn irqsave_round_trip_noop() {
        let s: Spinlock<u32, Buddy> = Spinlock::new(0);
        let mut g = s.lock_irqsave::<NoopIrq>();
        *g = 99;
        drop(g);
        assert_eq!(*s.lock(), 99);
    }

    #[test]
    fn lock_classes_have_distinct_ranks() {
        assert!(Buddy::rank() < Slab::rank());
        assert!(Slab::rank() < PageTable::rank());
        // kernfs node locks sit strictly between Dentry and Superblock so a
        // pseudo-fs may hold its structural lock WHILE taking the SB icache
        // lock (iget) — ascending, deadlock-free. (inode D2 lock-rank reorder.)
        assert!(Dentry::rank() < Kernfs::rank());
        assert!(Kernfs::rank() < Superblock::rank());
    }
}
