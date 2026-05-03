// `spawn_kernel_thread` — real kthread spawn per `13§4`.
//
// Allocates a kernel stack, builds the per-arch HAL `Context`
// scaffold via `Context::new_kernel_with_irq_frame` (so the kthread
// can be entered via the IRQ-tail epilogue per `14§R07`), wraps the
// task in `Arc<Task>`, and enqueues it on the global runqueue's
// CFS class. Idle tasks are constructed by `install_default_runqueue`
// in `schedule.rs`; this path is for runnable kthreads only.
//
// Stack discipline (`13§5` + `14§5`):
//   - 16 KiB default per kthread (matches the prior ksched.rs shim).
//   - Stack is a `Box<[u8]>` owned by the `Task`; freed when the
//     last `Arc<Task>` strong ref drops.
//   - `kernel_stack` AtomicPtr stores the top-of-stack (one past
//     the last byte) for `set_rsp0` / per-arch entry use.
//
// Class assignment v1: every kthread is `SchedClass::Normal { weight=1024 }`
// (Linux nice=0). RT spawn is a follow-up that wires `13§3` priorities.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use hal::Context;
use sched::{SchedClass, Task};

#[cfg(target_arch = "x86_64")]
type ArchCtx = hal_x86_64::ContextX86_64;
#[cfg(target_arch = "aarch64")]
type ArchCtx = hal_aarch64::ContextAArch64;

/// Default kthread stack size. Mirrors the prior ksched.rs shim;
/// `13§5` doesn't pin a number — Linux uses 16 KiB on x86_64 too.
pub const KTHREAD_STACK_BYTES: usize = 16 * 1024;

/// Linux nice=0 weight per the CFS prio→weight table. v1 every
/// spawned kthread runs at nice=0 until `sched_setscheduler` lands.
pub const DEFAULT_WEIGHT: u32 = 1024;

/// Errors `spawn_kernel_thread` can return.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SpawnError {
    /// No global runqueue installed — boot path didn't run
    /// `install_default_runqueue` yet.
    NoRunqueue,
}

/// Spawn a runnable kernel thread under the global runqueue.
///
/// Returns the `Arc<Task>` so the caller (typically a smoke
/// driver) can read tid / poll done. The task is enqueued in the
/// CFS class with `vruntime=0` (will be lifted to `min_vruntime`
/// on first pick if the RQ already advanced).
///
/// # SAFETY: caller is the boot path or a kthread on the same CPU
/// the runqueue serves; allocator + per-arch HAL state up; the
/// runqueue installed via `install_default_runqueue`. The returned
/// task's stack memory is owned by the `Arc` — callers must not
/// drop the last strong ref while the task is still running.
/// # C: O(stack_size) zero-fill + O(log N) CFS insert
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn spawn_kernel_thread(
    tid: u32,
    name: &'static str,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
) -> Result<Arc<Task>, SpawnError> {
    let rq = match super::runqueue::global() {
        Some(r) => r,
        None    => return Err(SpawnError::NoRunqueue),
    };

    // 1. Build the Task carrier (no stack, default vruntime).
    let class = SchedClass::Normal { weight: DEFAULT_WEIGHT };
    let mut task = Task::new(tid, name, class);

    // 2. Allocate + install kernel stack.
    let stack: Box<[u8]> = alloc::vec![0u8; KTHREAD_STACK_BYTES].into_boxed_slice();
    // SAFETY: `task` is local; no concurrent reader of kernel_stack
    // exists yet. install_stack stores top-of-stack atomically.
    unsafe { task.install_stack(stack); }
    let stack_top = task.kernel_stack.load(Ordering::Acquire);

    // 3. Build the per-arch HAL Context onto the stack scaffold.
    // SAFETY: stack_top is the freshly-installed top-of-stack, 16-byte aligned per Box's u8 alignment + KTHREAD_STACK_BYTES being a 16-multiple; entry is a valid extern "C" fn(usize)->!; the new_kernel_with_irq_frame layout reserves the bytes it writes below stack_top per `14§R07`. arch_ctx_ptr<ArchCtx>() asserts size fits.
    unsafe {
        let p = task.arch_ctx_ptr::<ArchCtx>();
        core::ptr::write(p, ArchCtx::new_kernel_with_irq_frame(stack_top, entry, arg));
    }

    // 4. Wrap, enqueue, return.
    let arc = Arc::new(task);
    {
        let mut inner = rq.inner.lock();
        inner.enqueue(Arc::clone(&arc));
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
    }
    Ok(arc)
}
