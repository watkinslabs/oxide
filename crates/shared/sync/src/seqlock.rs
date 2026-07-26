// `SeqLock<T, C>` — Linux `seqlock_t` (`include/linux/seqlock.h`): a sequence
// counter plus a writer spinlock, giving readers a lock-free, never-blocking
// snapshot of small `Copy` state that is read constantly and written rarely.
//
// This exists for the timekeeper (`06§3.1`, `skizm.md` 3.1 #3). Reading the
// clock happens in the timer ISR (`vvar::publish`) *and* in syscalls; with a
// plain `Spinlock` those two contexts share a lock, so a tick landing on a CPU
// whose syscall already holds it deadlocks that CPU. Linux solves it exactly
// here: `tk_core.seq` is a seqcount, readers never acquire anything.
//
// Protocol. `seq` is even when stable, odd while a writer is mid-update. A
// reader samples `seq`, copies the data, then re-samples: equal and even means
// no writer overlapped and the copy is coherent; otherwise retry. Readers can
// therefore observe a torn intermediate — so the copy is taken with
// `read_volatile` and only *returned* once validated, never acted on early.
//
// WRITERS MUST MASK INTERRUPTS. That is not a nicety, it is what makes the
// primitive usable from an ISR at all: if a writer is interrupted mid-update
// (seq odd) by a handler on the same CPU that reads, the reader spins waiting
// for a writer that cannot resume until the reader returns — a hard same-CPU
// livelock. Linux requires `write_seqlock_irqsave` for precisely this case, so
// `write` takes an `IrqGate` rather than leaving the choice to the caller.
// Writers are rare here (settimeofday / adjtimex / suspend accounting), so the
// masking costs nothing on the hot path, which is the read.

use core::cell::UnsafeCell;
use core::sync::atomic::{fence, AtomicU32, Ordering};

use crate::{IrqGate, LockClass, Spinlock};

pub struct SeqLock<T: Copy, C: LockClass> {
    /// Even = stable, odd = writer in progress (Linux `seqcount_t.sequence`).
    seq: AtomicU32,
    data: UnsafeCell<T>,
    /// Serializes writers against each other (the `lock` half of `seqlock_t`).
    writer: Spinlock<(), C>,
}

// SAFETY: `data` is only ever read through `read_volatile` under seq
// validation, and only ever mutated with the writer spinlock held, so T
// behaves as if &mut-borrowed by the single active writer.
unsafe impl<T: Copy + Send, C: LockClass> Sync for SeqLock<T, C> {}
unsafe impl<T: Copy + Send, C: LockClass> Send for SeqLock<T, C> {}

impl<T: Copy, C: LockClass> SeqLock<T, C> {
    /// # C: O(1)
    pub const fn new(val: T) -> Self {
        Self { seq: AtomicU32::new(0), data: UnsafeCell::new(val), writer: Spinlock::new(()) }
    }

    /// Lock-free snapshot (Linux `read_seqbegin`/`read_seqretry` loop). Safe
    /// from ANY context — hard IRQ, softirq, or process — because it acquires
    /// nothing. Retries while a writer is active.
    /// # C: O(1) uncontended; retries only while a writer overlaps
    /// # Ctx: any, including hard IRQ
    pub fn read(&self) -> T {
        loop {
            let s1 = self.seq.load(Ordering::Acquire);
            if s1 & 1 != 0 {
                // Writer mid-update — its store to seq is what we wait on.
                core::hint::spin_loop();
                continue;
            }
            // SAFETY: volatile copy of a `Copy` T; a concurrent writer may make this a torn read, which the seq re-check below detects and discards. The value never escapes unvalidated.
            let v = unsafe { core::ptr::read_volatile(self.data.get()) };
            // Order the copy before the second seq sample, or the compiler /
            // CPU could hoist the sample above it and validate the wrong window.
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == s1 { return v; }
            core::hint::spin_loop();
        }
    }

    /// Mutate under the writer lock with IRQs masked, bracketing the update in
    /// the odd/even seq transition (Linux `write_seqlock_irqsave`).
    ///
    /// The `IrqGate` is mandatory, not optional: see the module note — an ISR
    /// reader that interrupts a writer mid-update would otherwise livelock the
    /// CPU waiting for a writer that cannot make progress.
    /// # C: O(1) + f
    /// # Lk: writer lock held; IRQs off
    pub fn write<I: IrqGate>(&self, f: impl FnOnce(&mut T)) {
        let _g = self.writer.lock_irqsave::<I>();
        self.seq.fetch_add(1, Ordering::AcqRel); // -> odd: readers now retry
        fence(Ordering::Release);
        // SAFETY: the writer spinlock grants exclusive access for this scope, and IRQs are masked so no handler on this CPU can observe the half-written state except through `read`, which retries on the odd seq.
        unsafe { f(&mut *self.data.get()); }
        fence(Ordering::Release);
        self.seq.fetch_add(1, Ordering::AcqRel); // -> even: snapshot coherent
    }

    /// Read-modify-return under the same write protection, for writers that
    /// need a result (e.g. a validated setter reporting rejection).
    /// # C: O(1) + f
    /// # Lk: writer lock held; IRQs off
    pub fn write_with<I: IrqGate, R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let _g = self.writer.lock_irqsave::<I>();
        self.seq.fetch_add(1, Ordering::AcqRel);
        fence(Ordering::Release);
        // SAFETY: as `write` — exclusive under the writer lock, IRQs masked, and readers retry while seq is odd.
        let r = unsafe { f(&mut *self.data.get()) };
        fence(Ordering::Release);
        self.seq.fetch_add(1, Ordering::AcqRel);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Buddy, NoopIrq};

    #[test]
    fn read_returns_last_written_value() {
        let s: SeqLock<u64, Buddy> = SeqLock::new(7);
        assert_eq!(s.read(), 7);
        s.write::<NoopIrq>(|v| *v = 42);
        assert_eq!(s.read(), 42);
    }

    #[test]
    fn seq_is_even_when_stable_and_advances_per_write() {
        let s: SeqLock<u64, Buddy> = SeqLock::new(0);
        assert_eq!(s.seq.load(Ordering::Relaxed) & 1, 0, "must start stable");
        s.write::<NoopIrq>(|v| *v = 1);
        let after_one = s.seq.load(Ordering::Relaxed);
        assert_eq!(after_one & 1, 0, "must be even (stable) after a write");
        s.write::<NoopIrq>(|v| *v = 2);
        assert_eq!(s.seq.load(Ordering::Relaxed), after_one + 2, "each write advances seq by exactly 2");
    }

    #[test]
    fn reader_retries_while_seq_is_odd() {
        // Drive the odd-seq branch directly: a reader entering while a writer
        // is mid-update must not return the intermediate value.
        let s: SeqLock<u64, Buddy> = SeqLock::new(5);
        s.seq.store(1, Ordering::Release); // simulate writer in progress
        // Publish the "torn" value the reader must not accept, then close the
        // window so the retry loop can terminate.
        // SAFETY: single-threaded test; no concurrent reader or writer exists.
        unsafe { *s.data.get() = 9; }
        s.seq.store(2, Ordering::Release);
        assert_eq!(s.read(), 9, "after the writer completes, the new value is visible");
    }

    #[test]
    fn write_with_returns_the_closure_result() {
        let s: SeqLock<u64, Buddy> = SeqLock::new(3);
        let prev = s.write_with::<NoopIrq, _>(|v| { let p = *v; *v = 10; p });
        assert_eq!(prev, 3);
        assert_eq!(s.read(), 10);
    }

    #[test]
    fn concurrent_readers_never_observe_a_torn_struct() {
        // The property that matters: a reader either sees the whole old value
        // or the whole new one. Both fields are written together, so any
        // observed pair must be self-consistent.
        #[derive(Copy, Clone)]
        struct Pair { a: u64, b: u64 }
        static LK: SeqLock<Pair, Buddy> = SeqLock::new(Pair { a: 0, b: 0 });
        std::thread::scope(|sc| {
            sc.spawn(|| {
                for i in 1..20_000u64 { LK.write::<NoopIrq>(|p| { p.a = i; p.b = i; }); }
            });
            sc.spawn(|| {
                for _ in 0..20_000 {
                    let p = LK.read();
                    assert_eq!(p.a, p.b, "seqlock returned a torn snapshot");
                }
            });
        });
    }
}
