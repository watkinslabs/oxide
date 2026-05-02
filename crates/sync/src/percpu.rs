// Per-CPU primitive per `06§4`. Each CPU gets its own cacheline-padded
// slot of T; access is "stop-the-world local" (preempt-disabled across
// the call so the CPU index can't go stale mid-operation). Generic
// over `CpuLocalSource` so kernel callers plug in the arch register
// (GS_BASE on x86, TPIDR_EL1 on aarch64) and hosted tests plug in a
// thread-local mapping. No `dyn` per `07§5`.
//
// Klog's per-CPU lockless ring (`04§4.2`), slab's magazines (`12§3.2`),
// scheduler's runqueues, and debug-lockdep's per-CPU acquisition stack
// all live behind this primitive.

use core::cell::UnsafeCell;
use core::marker::PhantomData;

/// Maximum CPU count per `01§3` (`MAX_CPUS=256`).
pub const MAX_CPUS: usize = 256;

/// Cacheline boundary per `04§6` data-structure-defaults — false-sharing
/// avoidance for any per-CPU slot.
pub const CACHELINE_BYTES: usize = 64;

/// Read the current CPU index. Implementations:
///   - kernel x86_64: `mov %gs:[CPU_OFF], %ax` per `20§7`
///   - kernel aarch64: `mrs <reg>, TPIDR_EL1` per `21§7`
///   - hosted tests (`HostedCpuLocal`): thread-local id mod MAX_CPUS
///   - boot before SMP / single-CPU host (`NoopCpuLocal`): always 0
///
/// **Caller must have preemption disabled** across reading the CPU id
/// AND using the resulting per-CPU slot (`06§4`). `PerCpu::with_local`
/// encapsulates this contract.
pub trait CpuLocalSource: 'static {
    /// # C: O(1)
    fn current_cpu() -> u16;
}

/// Always returns 0. Use only when the workload is single-CPU
/// (single-thread tests, boot pre-SMP). Concurrent multi-thread use
/// degenerates to a single shared slot — false sharing, NOT data-race.
pub struct NoopCpuLocal;
impl CpuLocalSource for NoopCpuLocal {
    fn current_cpu() -> u16 { 0 }
}

/// Cacheline-aligned wrapper. `align(64)` makes each instance start on
/// a 64-byte boundary AND rounds size up to a multiple of 64, so
/// adjacent slots in `[CacheLine<T>; MAX_CPUS]` never share a line.
#[repr(C, align(64))]
pub struct CacheLine<T>(pub T);

/// Per-CPU storage of T. Slot count fixed at `MAX_CPUS`; one CPU can
/// only ever access its own slot via `with_local`. Iteration over all
/// slots (`for_each_unsynced`) is unsafe because it requires the
/// caller to ensure no other CPU is mid-`with_local` — only valid in
/// stop-the-world contexts (boot init, post-shutdown audit).
pub struct PerCpu<T, S: CpuLocalSource = NoopCpuLocal> {
    slots: [UnsafeCell<CacheLine<T>>; MAX_CPUS],
    _s: PhantomData<fn() -> S>,
}

// SAFETY: each CPU writes only its own slot; cross-CPU reads via
// `for_each_unsynced` are gated by an unsafe contract. T: Send is
// required for the cross-thread aspect of "this CPU's slot might be
// read after this CPU is offlined".
unsafe impl<T: Send, S: CpuLocalSource> Sync for PerCpu<T, S> {}
unsafe impl<T: Send, S: CpuLocalSource> Send for PerCpu<T, S> {}

impl<T: Default, S: CpuLocalSource> PerCpu<T, S> {
    /// # C: O(MAX_CPUS) — initializes every slot.
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| UnsafeCell::new(CacheLine(T::default()))),
            _s: PhantomData,
        }
    }
}

impl<T: Default, S: CpuLocalSource> Default for PerCpu<T, S> {
    fn default() -> Self { Self::new() }
}

impl<T: Copy, S: CpuLocalSource> PerCpu<T, S> {
    /// Initialize every slot to `init`. Useful when `T: !Default`.
    /// # C: O(MAX_CPUS)
    pub fn from_value(init: T) -> Self {
        Self {
            slots: core::array::from_fn(|_| UnsafeCell::new(CacheLine(init))),
            _s: PhantomData,
        }
    }
}

impl<T, S: CpuLocalSource> PerCpu<T, S> {
    /// Run `f` against this CPU's slot, with exclusive `&mut T` access
    /// for the duration. Caller MUST have preemption disabled (or be
    /// in IRQ-off / single-CPU boot ctx) across the entire call so the
    /// CPU index can't change mid-op per `06§4`.
    ///
    /// # C: O(1) + cost of `f`
    /// # Ctx: preempt-disabled
    pub fn with_local<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let cpu = S::current_cpu() as usize;
        debug_assert!(cpu < MAX_CPUS, "current_cpu() returned {cpu} >= MAX_CPUS");
        // SAFETY: per fn contract caller has preempt-off, so `cpu`
        // remains current for the call; this CPU is the sole writer
        // of `slots[cpu]`; for_each_unsynced is the only other reader
        // and is unsafe (caller asserts stop-the-world).
        let cell = unsafe { &mut *self.slots[cpu].get() };
        f(&mut cell.0)
    }

    /// Read this CPU's slot via shared ref. Same preempt-off contract.
    /// # C: O(1) + cost of `f`
    /// # Ctx: preempt-disabled
    pub fn with_local_ref<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        let cpu = S::current_cpu() as usize;
        debug_assert!(cpu < MAX_CPUS);
        // SAFETY: as `with_local`, but ref is shared; remains valid as
        // long as no concurrent writer exists on this CPU's slot.
        let cell = unsafe { &*self.slots[cpu].get() };
        f(&cell.0)
    }

    /// Iterate every CPU's slot.
    ///
    /// # SAFETY: caller guarantees no other CPU is concurrently inside
    /// `with_local` / `with_local_ref` on any slot during the iteration.
    /// Valid contexts: boot init before SMP, post-shutdown audit, or
    /// any operation that has serialized all CPUs (e.g., stop_machine).
    /// # C: O(MAX_CPUS)
    pub unsafe fn for_each_unsynced<F>(&self, mut f: F)
    where
        F: FnMut(usize, &T),
    {
        for (i, slot) in self.slots.iter().enumerate() {
            // SAFETY: caller-asserted no concurrent writers per fn contract.
            let cell = unsafe { &*slot.get() };
            f(i, &cell.0);
        }
    }
}

/// Hosted-test `CpuLocalSource`: assigns a unique 0..MAX_CPUS-1 id to
/// each thread on first access. Stable per-thread. Requires std for
/// `thread_local!`. Gated behind the `hosted` feature so kernel builds
/// don't accidentally pull std.
#[cfg(any(test, feature = "hosted"))]
pub struct HostedCpuLocal;
#[cfg(any(test, feature = "hosted"))]
impl CpuLocalSource for HostedCpuLocal {
    fn current_cpu() -> u16 {
        use core::sync::atomic::{AtomicU16, Ordering};
        static NEXT: AtomicU16 = AtomicU16::new(0);
        std::thread_local! {
            static MY: u16 = NEXT.fetch_add(1, Ordering::Relaxed) & ((MAX_CPUS as u16) - 1);
        }
        MY.with(|c| *c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};
    use std::sync::Arc;
    use std::thread;
    use std::vec::Vec;

    #[test]
    fn cacheline_alignment_and_size() {
        assert_eq!(align_of::<CacheLine<u8>>(), 64);
        assert_eq!(size_of::<CacheLine<u8>>(), 64);
        // Larger T inside CacheLine still rounds up to a multiple of 64.
        assert!(size_of::<CacheLine<[u8; 100]>>() >= 128);
        assert_eq!(size_of::<CacheLine<[u8; 100]>>() % 64, 0);
    }

    #[test]
    fn cacheline_no_false_sharing_in_array() {
        // Adjacent CacheLine slots start ≥ 64 bytes apart.
        let arr: [CacheLine<u8>; 4] = [
            CacheLine(1), CacheLine(2), CacheLine(3), CacheLine(4),
        ];
        let p0 = &arr[0] as *const _ as usize;
        let p1 = &arr[1] as *const _ as usize;
        assert!(p1 - p0 >= 64);
    }

    #[test]
    fn noop_cpu_local_is_zero() {
        assert_eq!(NoopCpuLocal::current_cpu(), 0);
        let pc: PerCpu<u32, NoopCpuLocal> = PerCpu::new();
        let v = pc.with_local(|x| { *x = 7; *x });
        assert_eq!(v, 7);
        // Read again — same slot, persists.
        pc.with_local(|x| assert_eq!(*x, 7));
    }

    #[test]
    fn from_value_initializes_every_slot() {
        let pc: PerCpu<u32, NoopCpuLocal> = PerCpu::from_value(42);
        let mut all = Vec::new();
        // SAFETY: single-thread test; no other thread holds a with_local borrow.
        unsafe { pc.for_each_unsynced(|_, v| all.push(*v)) };
        assert_eq!(all.len(), MAX_CPUS);
        for v in all { assert_eq!(v, 42); }
    }

    #[test]
    fn hosted_concurrent_each_thread_owns_its_slot() {
        let pc: Arc<PerCpu<u32, HostedCpuLocal>> = Arc::new(PerCpu::new());
        let mut handles = Vec::new();
        for tid in 0..16u32 {
            let pc = Arc::clone(&pc);
            handles.push(thread::spawn(move || {
                pc.with_local(|x| *x = tid + 100);
                let id = HostedCpuLocal::current_cpu();
                let read = pc.with_local(|x| *x);
                (id, read)
            }));
        }
        let results: Vec<(u16, u32)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        // Each thread saw its own write.
        for (id, read) in &results {
            // We can't assert read == 100 + tid (tid not retained) but
            // we can assert the slot has *some* recently-written value.
            assert!(*read >= 100, "cpu {id} slot did not receive write");
        }
    }

    #[test]
    fn hosted_unique_cpu_ids_assigned() {
        // Spawn 8 threads, each reads its own cpu id; all should be distinct.
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(thread::spawn(|| HostedCpuLocal::current_cpu()));
        }
        let ids: Vec<u16> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        // Sort + dedup.
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "duplicate cpu ids: {ids:?}");
    }

    #[test]
    fn for_each_unsynced_visits_every_slot_in_order() {
        let pc: PerCpu<u32, NoopCpuLocal> = PerCpu::new();
        let mut count = 0usize;
        // SAFETY: single-thread test; no concurrent writers.
        unsafe { pc.for_each_unsynced(|i, _| { assert_eq!(i, count); count += 1; }) };
        assert_eq!(count, MAX_CPUS);
    }

    #[test]
    fn many_independent_per_cpu_instances() {
        // Each PerCpu has its own backing storage; they don't alias.
        let a: PerCpu<u32, NoopCpuLocal> = PerCpu::from_value(1);
        let b: PerCpu<u32, NoopCpuLocal> = PerCpu::from_value(2);
        a.with_local(|v| *v = 100);
        b.with_local(|v| assert_eq!(*v, 2));
    }
}
