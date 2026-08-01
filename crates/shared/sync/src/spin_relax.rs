// The one relax step every spin loop in this crate takes.
//
// `pause` alone is enough on Linux, because Linux guarantees no kernel path
// spins unboundedly with interrupts masked: `smp_call_function_many_cond`
// asserts `lockdep_assert_irqs_enabled()` ("Can deadlock when called with
// interrupts disabled", `kernel/smp.c`), and `mmap_lock` is a sleeping lock, so
// a CPU waiting for an address-space lock is descheduled and keeps taking IPIs.
//
// This port runs syscalls with IF=0 (IA32_FMASK) and faults under interrupt
// gates, and its address-space lock is a spinning rwlock. That closes a cycle
// the x86 TLB-shootdown protocol cannot break on its own:
//
//   CPU A: holds the mm's VMA write lock -> `flush_tlb_others` -> waits for B's
//          0x42 ACK, interrupts masked.
//   CPU B: spinning for that same VMA lock with interrupts masked -> never
//          takes the 0x42 IPI -> never ACKs.
//
// B1476 observed exactly this: `[TLB-STUCK] cpu=1 pending=0x1 va=ALL round=2277`
// repeating while CPU0's NMI backtrace sat at a fixed rip inside
// `syscalls::userbuf::covered_by`'s `find_vma` -> `RwLock::read` spin. The old
// code hid it by abandoning the round after 1e9 spins and letting the caller
// free the frame anyway — a use-after-free with a live writable translation on
// the peer.
//
// So the spin itself services pending cross-CPU work. `arch-irq::tlb::install`
// wires the hook to `tlb::service()`, which takes no locks and is idempotent —
// the same deadlock-breaker `shootdown`'s own acquire loop already ran, now
// reaching every spin instead of only sender-vs-sender. aarch64 installs
// nothing: `tlbi vae1is` broadcasts in hardware, so there is no ACK to owe.

use core::sync::atomic::{AtomicPtr, Ordering};

/// Work a spinning CPU must service so it cannot starve a peer that is waiting
/// on it. Must take no locks and must be safe to call at any point a spin can
/// occur, including with interrupts masked and from interrupt context.
pub type SpinRelaxFn = fn();

static HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the relax hook. Boot path, once, after the IPI vector is live.
/// # SAFETY: `f` must take no locks and be reentrant — it runs from inside
/// arbitrary lock spins, including with interrupts masked.
/// # C: O(1)
pub unsafe fn set_spin_relax_hook(f: SpinRelaxFn) { HOOK.store(f as *mut (), Ordering::Release); }

/// One iteration of a spin wait: the architectural pause, then any cross-CPU
/// work this CPU owes. Every spin loop in this crate goes through here, so
/// there is exactly one place that decides what a spinning CPU still does.
/// # C: O(1) plus the installed hook
#[inline]
pub fn relax() {
    core::hint::spin_loop();
    // Hosted builds have no one-thread-per-CPU guarantee: the OS can
    // deschedule a lock holder while every waiter burns a whole core, turning
    // a bounded kernel spin into an unbounded hosted livelock. B1653 caught a
    // `net` test binary wedged at ~4300% CPU this way — 30-odd threads in
    // `Spinlock::lock` making no progress, orphaned from a completed run.
    // Yielding hands the core back so the holder can finish. Never compiled
    // into a kernel target, where the pause alone is the correct behavior.
    #[cfg(all(not(target_os = "oxide-kernel"), any(test, feature = "hosted")))]
    hosted_yield();
    let p = HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: `HOOK` is only ever written by `set_spin_relax_hook` from a
    // `SpinRelaxFn`, whose contract is no-locks and reentrant; non-null implies
    // a live 'static fn pointer with that exact signature.
    let f: SpinRelaxFn = unsafe { core::mem::transmute(p) };
    f();
}

/// Yield this OS thread once every `HOSTED_SPINS_PER_YIELD` relax steps. Pure
/// pausing keeps a short critical section fast; the periodic yield is what
/// bounds the wait when the holder is not currently on a core. # C: O(1)
#[cfg(all(not(target_os = "oxide-kernel"), any(test, feature = "hosted")))]
fn hosted_yield() {
    const HOSTED_SPINS_PER_YIELD: u32 = 4_096;
    std::thread_local! {
        static SPINS: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
    }
    SPINS.with(|spins| {
        let next = spins.get() + 1;
        if next < HOSTED_SPINS_PER_YIELD { spins.set(next); return; }
        spins.set(0);
        std::thread::yield_now();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32;

    static CALLS: AtomicU32 = AtomicU32::new(0);
    fn count() { CALLS.fetch_add(1, Ordering::Relaxed); }

    #[test]
    fn relax_is_inert_until_a_hook_is_installed_and_then_runs_it() {
        // Serialised by being the only test that touches HOOK.
        HOOK.store(core::ptr::null_mut(), Ordering::Release);
        CALLS.store(0, Ordering::Relaxed);
        relax();
        assert_eq!(CALLS.load(Ordering::Relaxed), 0, "no hook ⇒ pause only");
        // SAFETY: `count` takes no locks and is reentrant.
        unsafe { set_spin_relax_hook(count); }
        relax();
        relax();
        assert_eq!(CALLS.load(Ordering::Relaxed), 2, "every spin iteration services the hook");
        HOOK.store(core::ptr::null_mut(), Ordering::Release);
    }
}
