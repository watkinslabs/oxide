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
use vmm::AddressSpace;

#[cfg(target_arch = "x86_64")]
type ArchCtx = hal_x86_64::ContextX86_64;
#[cfg(target_arch = "aarch64")]
type ArchCtx = hal_aarch64::ContextAArch64;

/// Per-arch shim invoking `<ArchCtx>::new_user_with_irq_frame`.
/// Both impls are inherent (not on the `hal::Context` trait) so
/// dispatch goes through this thin shim.
#[cfg(target_arch = "x86_64")]
fn build_user_arch_ctx(stack_top: *mut u8, user_ip: u64, user_sp: u64) -> ArchCtx {
    ArchCtx::new_user_with_irq_frame(stack_top, user_ip, user_sp)
}
#[cfg(target_arch = "aarch64")]
fn build_user_arch_ctx(stack_top: *mut u8, user_ip: u64, user_sp: u64) -> ArchCtx {
    ArchCtx::new_user_with_irq_frame(stack_top, user_ip, user_sp)
}

/// Default kthread stack size. Mirrors the prior ksched.rs shim;
/// `13§5` doesn't pin a number — Linux uses 16 KiB on x86_64 too.
pub const KTHREAD_STACK_BYTES: usize = 16 * 1024;

/// Linux nice=0 weight per the CFS prio→weight table. v1 every
/// spawned kthread runs at nice=0 until `sched_setscheduler` lands.
pub const DEFAULT_WEIGHT: u32 = 1024;

/// Monotonic TID source per `01§1`. Tids 1..0xFFF reserved for
/// init / user-space identifiers populated externally; the
/// kernel-side spawn paths hand out from 0x1000 upward. Wraps to
/// 0x1000 on overflow (well past v1's expected task count).
static NEXT_TID: core::sync::atomic::AtomicU32
    = core::sync::atomic::AtomicU32::new(0x1000);

/// Allocate a fresh kernel-side TID. Strictly monotonic for v1.
/// # C: O(1)
pub fn next_tid() -> u32 {
    let t = NEXT_TID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if t < 0x1000 {
        // Wrapped — exceedingly unlikely v1 but recover gracefully.
        NEXT_TID.store(0x1000, core::sync::atomic::Ordering::Relaxed);
        0x1000
    } else {
        t
    }
}

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

/// Spawn a user-mode task. Allocates a 16 KiB kernel stack,
/// builds the per-arch HAL `Context` scaffold via the user-mode
/// flavor of `new_*_with_irq_frame`, attaches `mm`, wraps in
/// `Arc<Task>`, and enqueues on the runqueue's CFS class. When
/// `schedule()` later picks this task, the asm IRQ epilogue
/// iretq/eret's into ring 3 / EL0 at `entry_va` with the stack
/// pointer at `user_sp`.
///
/// Both arches now supported. arm sp_el0 save/restore lives in
/// the IRQ frame asm + `Context::new_user_with_irq_frame` (P2-13e).
///
/// # SAFETY: caller is the boot path or kernel context on the
/// same CPU as the runqueue; user_as has been activated so the
/// new task's mm matches the live CR3 / TTBR0; PMM + per-arch
/// HAL up. The task's stack memory is owned by the returned
/// `Arc<Task>`.
/// # C: O(stack_size) zero-fill + O(log N) CFS insert
/// # Ctx: pre-init or kernel ctx; preempt-off
pub unsafe fn spawn_user_thread(
    tid: u32,
    name: &'static str,
    entry_va: u64,
    user_sp: u64,
    mm: Arc<AddressSpace>,
) -> Result<Arc<Task>, SpawnError> {
    let rq = match super::runqueue::global() {
        Some(r) => r,
        None    => return Err(SpawnError::NoRunqueue),
    };

    let class = SchedClass::Normal { weight: DEFAULT_WEIGHT };
    let mut task = Task::new_user(tid, name, class, mm);

    let stack: Box<[u8]> = alloc::vec![0u8; KTHREAD_STACK_BYTES].into_boxed_slice();
    // SAFETY: task is local; no concurrent reader.
    unsafe { task.install_stack(stack); }
    let stack_top = task.kernel_stack.load(Ordering::Acquire);

    // SAFETY: stack_top is freshly-installed top-of-stack; entry_va + user_sp are caller-validated user addresses; the synthetic IRQ frame uses USER selectors / EL0 SPSR so the shared epilogue's iretq/eret lands at CPL=3 / EL0.
    unsafe {
        let p = task.arch_ctx_ptr::<ArchCtx>();
        core::ptr::write(p, build_user_arch_ctx(stack_top, entry_va, user_sp));
    }

    let arc = Arc::new(task);
    {
        let mut inner = rq.inner.lock();
        inner.enqueue(Arc::clone(&arc));
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
    }
    Ok(arc)
}
