// Kernel-thread coroutine smokes per `13§4` / `14§4`.
//
// `smoke()` — single kthread: build an arch `Context`, switch in,
// kthread emits one log + switches back. Proves save/restore +
// trampoline end-to-end.
//
// `smoke_yield()` — three-way: boot → A → B → A → boot. Two
// kthreads cooperatively yield via `Context::switch`, exercising
// stack discipline across multiple non-trivial frames before a real
// scheduler runqueue lands.
//
// Gated under `debug-sched` per `04§3` (R05): production builds
// elide both call sites entirely.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU32, Ordering};
use hal::Context;

#[cfg(target_arch = "x86_64")]
type ArchCtx = hal_x86_64::ContextX86_64;
#[cfg(target_arch = "aarch64")]
type ArchCtx = hal_aarch64::ContextAArch64;

/// Coroutine pair held on the boot stack; the kthread's `arg`
/// points at this struct so it can `switch` back to `boot`.
#[repr(C)]
struct CoroPair {
    boot: ArchCtx,
    kt:   ArchCtx,
}

extern "C" fn first_kthread_entry(arg: usize) -> ! {
    klog::kinfo!("kthread: hello from first kernel thread");
    // SAFETY: `arg` was set by `smoke()` to the address of a
    // `CoroPair` on the boot stack; the boot frame is alive (its
    // execution is suspended inside `Context::switch`); single-CPU,
    // IRQ-off per pre-init contract.
    let pair = unsafe { &mut *(arg as *mut CoroPair) };
    // SAFETY: switching back restores the boot context (saved by
    // the original `switch` in `smoke()`); kthread state is saved
    // into `pair.kt` for completeness even though we never re-enter.
    unsafe { ArchCtx::switch(&mut pair.kt as *mut _, &pair.boot as *const _); }
    // Unreachable: switch-back resumes `smoke()` past its switch call.
    loop { core::hint::spin_loop(); }
}

/// Build a single kernel thread, switch into it once, and resume.
///
/// # SAFETY: caller is the boot path; runs single-CPU with IRQs
/// off; the global allocator is up. The CoroPair lives on the
/// boot stack; the kthread accesses it only during its single
/// switch-back, while the boot frame is paused.
/// # C: O(1) (one switch into + one switch back)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn smoke() {
    let mut stack: Box<[u8]> = alloc::vec![0u8; 16 * 1024].into_boxed_slice();
    // SAFETY: `stack.as_mut_ptr().add(stack.len())` is one past the
    // allocation, the standard "stack top" convention; `new_kernel`
    // writes one u64 below it on x86 and uses the value as SP on arm.
    let stack_top = unsafe { stack.as_mut_ptr().add(stack.len()) };
    // SAFETY: ArchCtx is `#[derive(Default)]`; zeroed bit pattern is a
    // valid all-fields-zero context whose contents are overwritten by
    // the SAVE half of the impending `switch` call.
    let mut pair: CoroPair = unsafe { core::mem::zeroed() };
    pair.kt = ArchCtx::new_kernel(
        stack_top,
        first_kthread_entry,
        &mut pair as *mut CoroPair as usize,
    );
    klog::kinfo!("kthread: switching to first kernel thread");
    // SAFETY: `pair.kt` was just constructed via `new_kernel`; its
    // saved sp points at the freshly-allocated stack; the trampoline
    // address is the kernel-target asm symbol; runs single-CPU with
    // preemption disabled (no scheduler yet).
    unsafe { ArchCtx::switch(&mut pair.boot as *mut _, &pair.kt as *const _); }
    klog::kinfo!("kthread: returned from first kernel thread");
    drop(stack);
}

// ---------------------------------------------------------------------------
// Three-way yield smoke (boot → A → B → A → boot)
// ---------------------------------------------------------------------------

/// Triple of contexts shared by both kthreads + the boot frame.
/// Pointer to this struct is passed via `arg` to each kthread.
#[repr(C)]
struct YieldTriple {
    boot: ArchCtx,
    a:    ArchCtx,
    b:    ArchCtx,
}

/// Counts cooperative yields observed by either kthread; verifies
/// the round-trip without smuggling state through statics.
static YIELD_COUNT: AtomicU32 = AtomicU32::new(0);

extern "C" fn kthread_a_entry(arg: usize) -> ! {
    klog::kinfo!("kthread-a: enter");
    YIELD_COUNT.fetch_add(1, Ordering::Relaxed);
    // SAFETY: `arg` is the address of a YieldTriple on the boot stack
    // that outlives this kthread; single-CPU, IRQ-off.
    let t = unsafe { &mut *(arg as *mut YieldTriple) };
    // SAFETY: switching to B saves A's state; B's saved sp is a fresh
    // 16 KiB kernel stack programmed with `new_kernel`.
    unsafe { ArchCtx::switch(&mut t.a as *mut _, &t.b as *const _); }
    // Re-entered when B yields back to A.
    klog::kinfo!("kthread-a: resumed after B");
    YIELD_COUNT.fetch_add(1, Ordering::Relaxed);
    // SAFETY: switch back to boot ends the smoke; boot's context was
    // saved by the original switch from `smoke_yield()`.
    unsafe { ArchCtx::switch(&mut t.a as *mut _, &t.boot as *const _); }
    loop { core::hint::spin_loop(); }
}

extern "C" fn kthread_b_entry(arg: usize) -> ! {
    klog::kinfo!("kthread-b: enter");
    YIELD_COUNT.fetch_add(1, Ordering::Relaxed);
    // SAFETY: same triple-pointer protocol as A; single-CPU, IRQ-off.
    let t = unsafe { &mut *(arg as *mut YieldTriple) };
    // SAFETY: yield back to A; A's saved sp points into A's stack
    // mid-`switch` call where it'll resume on return.
    unsafe { ArchCtx::switch(&mut t.b as *mut _, &t.a as *const _); }
    loop { core::hint::spin_loop(); }
}

/// Three-way cooperative yield: boot → A → B → A → boot.
///
/// # SAFETY: caller is the boot path; allocator up; single-CPU,
/// IRQs off. Both kthread stacks + the YieldTriple live across the
/// entire smoke; the triple is on the boot stack which stays alive
/// while either kthread is running (the boot frame is suspended).
/// # C: O(1) (4 switches total)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn smoke_yield() {
    let mut stack_a: Box<[u8]> = alloc::vec![0u8; 16 * 1024].into_boxed_slice();
    let mut stack_b: Box<[u8]> = alloc::vec![0u8; 16 * 1024].into_boxed_slice();
    // SAFETY: one-past-end stack-top convention; matches `new_kernel`'s expectation on both arches.
    let top_a = unsafe { stack_a.as_mut_ptr().add(stack_a.len()) };
    // SAFETY: one-past-end stack-top convention; matches `new_kernel`'s expectation on both arches.
    let top_b = unsafe { stack_b.as_mut_ptr().add(stack_b.len()) };
    // SAFETY: ArchCtx zeroed pattern is overwritten by the SAVE half
    // of the boot→A switch and by `new_kernel` for A and B below.
    let mut t: YieldTriple = unsafe { core::mem::zeroed() };
    let arg = &mut t as *mut YieldTriple as usize;
    t.a = ArchCtx::new_kernel(top_a, kthread_a_entry, arg);
    t.b = ArchCtx::new_kernel(top_b, kthread_b_entry, arg);

    YIELD_COUNT.store(0, Ordering::Relaxed);
    klog::kinfo!("kthread-yield: boot -> A");
    // SAFETY: A's context is freshly built; preemption disabled.
    unsafe { ArchCtx::switch(&mut t.boot as *mut _, &t.a as *const _); }
    let n = YIELD_COUNT.load(Ordering::Relaxed);
    klog::write_raw(b"[INFO]  kthread-yield: returned to boot, yields=");
    klog::write_dec_u64(n as u64);
    klog::write_raw(b"\n");
    drop(stack_a);
    drop(stack_b);
}
