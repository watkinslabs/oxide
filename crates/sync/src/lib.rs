// Synchronization primitives per docs/06§3. Crate-level home for
// Spinlock, RwLock, SeqLock, RCU once those land. This file ships
// Spinlock + LockClass + IrqGate; the rest land alongside their
// consumers in the dep order from `boot-flow.md`.

#![no_std]

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
}

macro_rules! decl_lock_class {
    ($($name:ident = $rank:literal),+ $(,)?) => {
        $(
            pub struct $name;
            impl LockClass for $name {
                fn rank() -> u16 { $rank }
            }
        )+
    };
}

decl_lock_class! {
    Buddy        =  0,
    Slab         = 10,
    PageTable    = 20,
    AddressSpace = 30,
    Inode        = 40,
    Dentry       = 50,
    Superblock   = 60,
    MountTable   = 70,
    FdTable      = 80,
    SignalQueue  = 90,
    TaskList     = 100,
    Runqueue     = 110,
    Tty          = 120,
    SocketTable  = 130,
    Socket       = 140,
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
    unsafe fn restore(_flags: u64) {}
}

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
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
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

    /// IRQ-safe lock per `06§3.1`. Disables IRQs via `IrqGate`, then
    /// spins for the lock. Restores on `Drop`.
    /// # C: O(contention)
    /// # Lk: this lock acquired; IRQs off
    pub fn lock_irqsave<I: IrqGate>(&self) -> IrqGuard<'_, T, C, I> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
