// Atomic counters per `37§3` PMU surface. Subset for v1 — software
// counters only, exposed by name; PMU (hardware perf events) need
// HAL CpuOps and ride later.
//
// Each `Counter` holds an `AtomicU64` plus a `&'static str` name so
// `/proc/stat` style readers can iterate by string. Global registry
// is `Spinlock<Vec<&'static Counter>>` — names register once at
// subsystem init and never go away.

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, Tty as ObsClass};

/// One software counter — name + value.
pub struct Counter {
    pub name:  &'static str,
    pub value: AtomicU64,
}

impl Counter {
    /// # C: O(1)
    pub const fn new(name: &'static str) -> Self {
        Self { name, value: AtomicU64::new(0) }
    }
    /// # C: O(1)
    pub fn get(&self) -> u64 { self.value.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn add(&self, n: u64) -> u64 {
        self.value.fetch_add(n, Ordering::AcqRel)
    }
    /// # C: O(1)
    pub fn inc(&self) -> u64 { self.add(1) }
    /// # C: O(1)
    pub fn reset(&self) { self.value.store(0, Ordering::Release); }
}

static REGISTRY: Spinlock<Vec<&'static Counter>, ObsClass> = Spinlock::new(Vec::new());

/// Register `c` so it shows up in `iter_all`. Idempotent: registering
/// the same `Counter` twice is a no-op.
/// # C: O(N)
pub fn register(c: &'static Counter) {
    let mut g = REGISTRY.lock();
    if !g.iter().any(|existing| core::ptr::eq(*existing, c)) {
        g.push(c);
    }
}

/// Snapshot of all registered counters as `(name, value)` pairs.
/// # C: O(N)
pub fn snapshot() -> Vec<(&'static str, u64)> {
    let g = REGISTRY.lock();
    g.iter().map(|c| (c.name, c.get())).collect()
}

/// True iff a counter with this name has been registered.
/// # C: O(N)
pub fn is_registered(name: &str) -> bool {
    let g = REGISTRY.lock();
    g.iter().any(|c| c.name == name)
}

/// Number of registered counters.
/// # C: O(1)
pub fn registered_count() -> usize {
    REGISTRY.lock().len()
}
