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

use hal::{Context, TimerOps};
use crate::{SchedClass, Task};
use vmm::AddressSpace;

#[inline]
fn monotonic_ns() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

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
    arc.spawn_ns.store(monotonic_ns(), Ordering::Release);
    super::registry::insert(&arc);
    {
        let mut inner = rq.inner.lock();
        inner.enqueue(Arc::clone(&arc));
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
    }
    // Per `13§9` wake→resched: a freshly-runnable task may
    // outrank the current; flag a reschedule so the next
    // preempt-enable / syscall-return point picks it up.
    crate::preempt::set_need_resched();
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
    // SAFETY: caller upholds spawn_user_thread_with_vpid's preconditions; vpid=0 means "use real tgid/tid" (no namespace remapping).
    unsafe { spawn_user_thread_with_vpid(tid, 0, 0, name, entry_va, user_sp, mm) }
}

/// Same as `spawn_user_thread` but stamps `vtgid` / `vtid` into the
/// new `Task` BEFORE registry insert + runqueue enqueue. Used by the
/// PID 1 spawn path: musl crt1 calls `set_tid_address` very early
/// and caches the return as `__libc.tid`, so the pid-namespace
/// virtualization MUST be in place by the time the task makes its
/// first syscall — race-free guarantees require setting it on the
/// `Task` before any other CPU / preemption point can observe it.
///
/// `vpid_tgid == 0` and `vpid_tid == 0` mean "no namespace
/// remapping" (Task::new_user defaults).
///
/// # SAFETY: same preconditions as `spawn_user_thread`.
/// # C: O(stack_size) zero-fill + O(log N) CFS insert
/// # Ctx: pre-init or kernel ctx; preempt-off
pub unsafe fn spawn_user_thread_with_vpid(
    tid: u32,
    vpid_tgid: u32,
    vpid_tid: u32,
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

    // F153-1: stamp namespace-visible pids on the local Task before
    // it's wrapped in Arc + made visible via registry/runqueue.
    if vpid_tgid != 0 { task.vtgid.store(vpid_tgid, Ordering::Release); }
    if vpid_tid  != 0 { task.vtid.store(vpid_tid,   Ordering::Release); }

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
    arc.spawn_ns.store(monotonic_ns(), Ordering::Release);
    super::registry::insert(&arc);
    {
        let mut inner = rq.inner.lock();
        inner.enqueue(Arc::clone(&arc));
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
    }
    // Per `13§9` wake→resched: same rule for user-thread spawn.
    crate::preempt::set_need_resched();
    Ok(arc)
}

/// Fork-specific user-task spawn (P5-10): identical to
/// `spawn_user_thread` but builds the arch ctx via the
/// fork-aware constructor that copies the parent's saved
/// syscall-frame regs into the child's iretq scratch slots and
/// the Context callee-saved fields. Child's `rax` is forced to 0
/// so the post-syscall return value is `fork() == 0`.
///
/// `entry_va` / `user_sp` come from `current_user_frame()` (the
/// parent's RIP just past the syscall + the parent's user RSP at
/// syscall time). `regs` is captured from
/// `current_user_full_frame()` BEFORE this call so the parent's
/// state is still intact on the saved stack.
///
/// # SAFETY: same preconditions as `spawn_user_thread`; in
/// addition `regs` must reflect the parent's saved-syscall state
/// (i.e., captured during dispatch on the parent's per-task
/// kernel stack).
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub unsafe fn spawn_user_thread_for_fork(
    tid: u32,
    name: &'static str,
    entry_va: u64,
    user_sp: u64,
    user_rflags: u64,
    regs: &hal_x86_64::ForkRegs,
    mm: Arc<AddressSpace>,
) -> Result<Arc<Task>, SpawnError> {
    let rq = match super::runqueue::global() {
        Some(r) => r,
        None    => return Err(SpawnError::NoRunqueue),
    };

    let class = SchedClass::Normal { weight: DEFAULT_WEIGHT };
    let mut task = Task::new_user(tid, name, class, mm);

    // Inherit credentials from the running parent. Parent is current()
    // since fork is a synchronous syscall on the parent's CPU. If
    // current() is None (boot path) the default Creds::root() stands.
    if let Some(parent) = super::current() {
        // SAFETY: parent is the running task on this CPU (single-mutator
        // invariant per `13§5`); `task` is local and not yet scheduled.
        unsafe { task.creds = parent.creds.snapshot(); }
        // F105: PID NS inheritance. If parent's unshare_pid_pending
        // is set, allocate a fresh pid_ns for the child + give it
        // vtgid=1 (it becomes the NS's "init"). Else inherit parent's
        // pid_ns + assign next vtgid in that NS (or 0 if init NS).
        let pending = parent.unshare_pid_pending.swap(false, Ordering::AcqRel);
        if pending {
            static NEXT_PID_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
            let ns = NEXT_PID_NS.fetch_add(1, Ordering::AcqRel);
            task.pid_ns.store(ns, Ordering::Release);
            task.vtgid.store(1, Ordering::Release);
            task.vtid.store(1, Ordering::Release);
        } else {
            let parent_ns = parent.pid_ns.load(Ordering::Acquire);
            task.pid_ns.store(parent_ns, Ordering::Release);
            if parent_ns != 0 {
                // Per-NS vpid allocator. v1 uses a single global counter
                // keyed by ns; collisions don't matter for the bounded
                // task set we run.
                static NEXT_VPID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(2);
                let v = NEXT_VPID.fetch_add(1, Ordering::AcqRel);
                task.vtgid.store(v, Ordering::Release);
                task.vtid.store(v, Ordering::Release);
            }
        }
    }

    let stack: Box<[u8]> = alloc::vec![0u8; KTHREAD_STACK_BYTES].into_boxed_slice();
    // SAFETY: task is local; no concurrent reader.
    unsafe { task.install_stack(stack); }
    let stack_top = task.kernel_stack.load(Ordering::Acquire);

    // F156: inherit parent's fs_base so CLONE_VM children see the same
    // TLS that musl/glibc set up via arch_prctl(ARCH_SET_FS). Without
    // this, all %fs:offs reads in the child go to (fs_base=0)+offs and
    // hit unmapped or wrong memory — busybox getty's argv-from-TLS path
    // ends up reading code-segment bytes as paths.
    let parent_fs_base = super::current()
        .map(|p| {
            // SAFETY: parent is the running task on this CPU; arch_ctx is single-mutator per `13§5`; we only read the fs_base field.
            unsafe { (*p.arch_ctx_ptr::<ArchCtx>()).fs_base }
        })
        .unwrap_or(0);
    // SAFETY: stack_top freshly installed; entry_va/user_sp/regs from parent's saved frame; new_user_for_fork lays out the iretq frame for ring-3 resume with regs preloaded.
    unsafe {
        let p = task.arch_ctx_ptr::<ArchCtx>();
        core::ptr::write(p, ArchCtx::new_user_for_fork(stack_top, entry_va, user_sp, user_rflags, regs, parent_fs_base));
    }

    let arc = Arc::new(task);
    arc.spawn_ns.store(monotonic_ns(), Ordering::Release);
    super::registry::insert(&arc);
    {
        let mut inner = rq.inner.lock();
        inner.enqueue(Arc::clone(&arc));
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
    }
    crate::preempt::set_need_resched();
    Ok(arc)
}

/// aarch64 mirror of `spawn_user_thread_for_fork`. The arm path
/// has no separate user_rflags arg (SPSR_EL1 is encoded inside
/// `ForkRegs.spsr_el1`); `entry_va` is the parent's saved ELR_EL1
/// (the post-SVC PC) and `user_sp` is either parent's SP_EL0 or
/// the clone(2)-supplied child stack.
/// # SAFETY: same preconditions as `spawn_user_thread`; in addition
/// `regs` must reflect the parent's saved-syscall state captured
/// during dispatch on the parent's per-task kernel stack.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub unsafe fn spawn_user_thread_for_fork(
    tid: u32,
    name: &'static str,
    entry_va: u64,
    user_sp: u64,
    regs: &hal_aarch64::ForkRegs,
    mm: Arc<AddressSpace>,
) -> Result<Arc<Task>, SpawnError> {
    let rq = match super::runqueue::global() {
        Some(r) => r,
        None    => return Err(SpawnError::NoRunqueue),
    };

    let class = SchedClass::Normal { weight: DEFAULT_WEIGHT };
    let mut task = Task::new_user(tid, name, class, mm);

    if let Some(parent) = super::current() {
        // SAFETY: parent is the running task on this CPU (single-mutator
        // invariant per `13§5`); `task` is local and not yet scheduled.
        unsafe { task.creds = parent.creds.snapshot(); }
    }

    let stack: Box<[u8]> = alloc::vec![0u8; KTHREAD_STACK_BYTES].into_boxed_slice();
    // SAFETY: task is local; no concurrent reader.
    unsafe { task.install_stack(stack); }
    let stack_top = task.kernel_stack.load(Ordering::Acquire);

    // SAFETY: stack_top freshly installed; entry_va/user_sp/regs from parent's saved frame; new_user_for_fork lays out the IRQ-epilogue frame for EL0 resume with regs preloaded.
    unsafe {
        let p = task.arch_ctx_ptr::<ArchCtx>();
        core::ptr::write(p, ArchCtx::new_user_for_fork(stack_top, entry_va, user_sp, regs));
    }

    let arc = Arc::new(task);
    arc.spawn_ns.store(monotonic_ns(), Ordering::Release);
    super::registry::insert(&arc);
    {
        let mut inner = rq.inner.lock();
        inner.enqueue(Arc::clone(&arc));
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
    }
    crate::preempt::set_need_resched();
    Ok(arc)
}
