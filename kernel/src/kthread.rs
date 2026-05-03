// First kernel-thread coroutine smoke. Per `13§4` / `14§4`: build
// an arch `Context` targeting an entry function, allocate a stack,
// and call `Context::switch` to yield into it. The thread emits one
// klog line and yields back via the same primitive — proving the
// save/restore + trampoline path end-to-end before a runqueue +
// preemption land in `crates/sched`.
//
// Gated under `debug-sched` per `04§3` (R05): production builds
// elide the call site entirely.

use alloc::boxed::Box;
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
