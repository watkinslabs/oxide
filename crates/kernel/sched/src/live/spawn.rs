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
    /// The concrete kernel-stack memcg charge was rejected.
    NoMem,
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

    // 2. Allocate + install the guard-paged kernel stack (CONFIG_VMAP_STACK).
    // SAFETY: `task` is local; no concurrent reader of kernel_stack exists yet.
    if !unsafe { task.install_stack() } { return Err(SpawnError::NoMem); }
    if !task.try_charge_kernel_stack(cgroup::kernel_context_memcg()) {
        return Err(SpawnError::NoMem);
    }
    let stack_top = task.kernel_stack.load(Ordering::Acquire);

    // 3. Build the per-arch HAL Context onto the stack scaffold.
    // SAFETY: stack_top is the freshly-installed top-of-stack, 16-byte aligned per Box's u8 alignment + KTHREAD_STACK_BYTES being a 16-multiple; entry is a valid extern "C" fn(usize)->!; the new_kernel_with_irq_frame layout reserves the bytes it writes below stack_top per `14§R07`. arch_ctx_ptr<ArchCtx>() asserts size fits.
    unsafe {
        let p = task.arch_ctx_ptr::<ArchCtx>();
        core::ptr::write(p, ArchCtx::new_kernel_with_irq_frame(stack_top, entry, arg));
    }

    // 4. Wrap, enqueue, return.
    let start_boottime_ns = monotonic_ns();
    task.start_boottime_ns = start_boottime_ns;
    let arc = Arc::new(task);
    arc.spawn_ns.store(start_boottime_ns, Ordering::Release);
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
    // B118: pgid/sid live in VPID space, not the opaque internal tid.
    // Task::new_user seeds both to the internal tid; for a user task with
    // a stamped vpid (init = 1) re-seed to vtgid so getpgid/getsid and
    // ps PGRP/SID report Linux pids. Forks override via clone (inherit
    // parent); kthreads (vpid 0) keep the internal tid (not user-visible).
    if vpid_tgid != 0 {
        task.set_pgid(vpid_tgid);
        task.set_sid(vpid_tgid);
    }

    // SAFETY: task is local; no concurrent reader. install_stack allocates a
    // guard-paged kernel stack (Linux CONFIG_VMAP_STACK) and stores its top.
    if !unsafe { task.install_stack() } { return Err(SpawnError::NoMem); }
    let stack_memcg = crate::current()
        .map(|task| cgroup::cgroup_of(task.tid as u64))
        .unwrap_or_else(cgroup::kernel_context_memcg);
    if !task.try_charge_kernel_stack(stack_memcg) {
        return Err(SpawnError::NoMem);
    }
    let stack_top = task.kernel_stack.load(Ordering::Acquire);

    // SAFETY: stack_top is freshly-installed top-of-stack; entry_va + user_sp are caller-validated user addresses; the synthetic IRQ frame uses USER selectors / EL0 SPSR so the shared epilogue's iretq/eret lands at CPL=3 / EL0.
    unsafe {
        let p = task.arch_ctx_ptr::<ArchCtx>();
        core::ptr::write(p, build_user_arch_ctx(stack_top, entry_va, user_sp));
    }

    let start_boottime_ns = monotonic_ns();
    task.start_boottime_ns = start_boottime_ns;
    let arc = Arc::new(task);
    arc.spawn_ns.store(start_boottime_ns, Ordering::Release);
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
    thread_group: Option<Arc<crate::thread_group::ThreadGroup>>,
) -> Result<Arc<Task>, SpawnError> {
    let _rq = match super::runqueue::global() {
        Some(r) => r,
        None    => return Err(SpawnError::NoRunqueue),
    };

    let class = SchedClass::Normal { weight: DEFAULT_WEIGHT };
    let mut task = Task::new_user(tid, name, class, mm);
    if let Some(group) = thread_group {
        task.join_thread_group(group);
    }

    // Inherit credentials from the running parent. Parent is current()
    // since fork is a synchronous syscall on the parent's CPU. If
    // current() is None (boot path) the default Creds::root() stands.
    if let Some(parent) = super::current() {
        // SAFETY: parent is the running task on this CPU (single-mutator
        // invariant per `13§5`); `task` is local and not yet scheduled.
        unsafe { task.creds = parent.creds.snapshot(); }
        // oom_score_adj is inherited across fork and CLONE_THREAD exactly as
        // Linux copies it in dup_task_struct.
        task.oom_score_adj.store(parent.oom_score_adj(), Ordering::Release);
        // PR_SET_TIMERSLACK state is inherited across fork and preserved by
        // exec, like Linux task_struct::timer_slack_ns.
        task.timer_slack_ns.store(parent.timer_slack_ns.load(Ordering::Acquire), Ordering::Release);
        // ioprio_set/get(2): I/O priority is inherited across fork.
        task.ioprio.store(parent.ioprio.load(Ordering::Acquire), Ordering::Release);
        // /proc/<pid>/exe is inherited across fork until the child execs (Linux
        // dup_mm carries exe_file). Also lets the wedge / [EXIT] dumps name a
        // pre-exec fork-child by the program that forked it.
        task.set_exe_path(parent.exe_path());
        // comm is inherited across fork/CLONE_THREAD exactly like Linux
        // copies task_struct::comm in dup_task_struct — a pthread_create'd
        // thread starts with the creator's name until it renames itself via
        // prctl(PR_SET_NAME)/pthread_setname_np.
        task.set_comm_bytes(parent.comm_bytes());
        // SUID_DUMP_* / THP_DISABLE are inherited across fork/clone (Linux
        // copies mm->flags).
        task.dumpable.store(parent.dumpable.load(Ordering::Acquire), Ordering::Release);
        task.thp_disable.store(parent.thp_disable.load(Ordering::Acquire), Ordering::Release);
        // Namespace publication runs after this allocation. Seed a visible PID;
        // clone namespace work replaces it with 1 when the child becomes a
        // new PID namespace's init task.
        static NEXT_VPID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(2);
        let v = NEXT_VPID.fetch_add(1, Ordering::AcqRel);
        task.vtgid.store(v, Ordering::Release);
        task.vtid.store(v, Ordering::Release);
        // Seccomp is INHERITED across fork/clone and PRESERVED across execve
        // (Linux copies the filter chain in dup_task_struct; execve never
        // clears it). Without this a seccomp-sandboxed process could fork() and
        // the child would run with an EMPTY filter set — a trivial sandbox
        // escape (`fork(); <forbidden syscall in child>`).
        // SAFETY: parent is the running task on this CPU (single-mutator read
        // per `13§5`); `task` is local and not yet scheduled (single-mutator
        // write). The child gets its own copy of the filter chain.
        unsafe { *task.seccomp_filters.get() = (*parent.seccomp_filters.get()).clone(); }
        // Landlock ruleset chain is likewise inherited across fork and kept
        // across execve — a Landlock-confined process's children stay confined.
        let parent_chain = parent.landlock_chain.lock().clone();
        *task.landlock_chain.lock() = parent_chain;
    }

    // SAFETY: task is local; no concurrent reader. install_stack allocates a
    // guard-paged kernel stack (Linux CONFIG_VMAP_STACK) and stores its top.
    if !unsafe { task.install_stack() } { return Err(SpawnError::NoMem); }
    let stack_top = task.kernel_stack.load(Ordering::Acquire);

    // F156 + B38: inherit parent's fs_base so CLONE_VM children see the
    // same TLS that musl/glibc set up via arch_prctl(ARCH_SET_FS).
    // Without this, all %fs:offs reads in the child go to
    // (fs_base=0)+offs and hit unmapped/wrong memory — getty's
    // argv-from-TLS path ends up reading code-segment bytes as paths.
    //
    // B38 fix: read the LIVE IA32_FS_BASE MSR rather than the saved
    // `arch_ctx.fs_base` field. arch_prctl(ARCH_SET_FS) writes the MSR
    // directly and only the next context switch syncs it back to
    // arch_ctx; a fork() that lands between the two would otherwise
    // pull a stale (often zero) value into the child. Mirrors the
    // aarch64 fork path which already reads live TPIDR_EL0 via mrs.
    // SAFETY: rdmsr IA32_FS_BASE at CPL=0 is unconditionally legal; we
    // are on the parent's syscall stack so the MSR holds the parent's
    // user FS_BASE.
    let parent_fs_base = unsafe { hal_x86_64::get_user_fs_base() };
    // SAFETY: stack_top freshly installed; entry_va/user_sp/regs from parent's saved frame; new_user_for_fork lays out the iretq frame for ring-3 resume with regs preloaded.
    unsafe {
        let p = task.arch_ctx_ptr::<ArchCtx>();
        core::ptr::write(p, ArchCtx::new_user_for_fork(stack_top, entry_va, user_sp, user_rflags, regs, parent_fs_base));
    }

    let start_boottime_ns = monotonic_ns();
    task.start_boottime_ns = start_boottime_ns;
    let arc = Arc::new(task);
    arc.spawn_ns.store(start_boottime_ns, Ordering::Release);
    // The caller publishes only after every fallible clone step completes.
    Ok(arc)
}

/// Publish a fully initialized clone in the task/PID registry. # C: O(N_tasks)
pub fn publish_new_task(task: &Arc<Task>) { super::registry::insert(task); }

/// Linux `wake_up_new_task`: make a freshly-built task (registered but not yet
/// runnable) schedulable. Call ONLY after every field a running child could
/// observe — FS_BASE/TLS, vtgid, fd table, sigmask, `set_child_tid` — is final,
/// so no CPU picks a half-constructed task. # C: O(1)
pub fn wake_new_task(task: &Arc<Task>) {
    let rq = match super::runqueue::global() { Some(r) => r, None => return };
    {
        let mut inner = rq.inner.lock();
        inner.enqueue(Arc::clone(task));
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
    }
    crate::preempt::set_need_resched();
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
    thread_group: Option<Arc<crate::thread_group::ThreadGroup>>,
) -> Result<Arc<Task>, SpawnError> {
    let _rq = match super::runqueue::global() {
        Some(r) => r,
        None    => return Err(SpawnError::NoRunqueue),
    };

    let class = SchedClass::Normal { weight: DEFAULT_WEIGHT };
    let mut task = Task::new_user(tid, name, class, mm);
    if let Some(group) = thread_group {
        task.join_thread_group(group);
    }

    if let Some(parent) = super::current() {
        // SAFETY: parent is the running task on this CPU (single-mutator
        // invariant per `13§5`); `task` is local and not yet scheduled.
        unsafe { task.creds = parent.creds.snapshot(); }
        // oom_score_adj is inherited across fork and CLONE_THREAD exactly as
        // Linux copies it in dup_task_struct.
        task.oom_score_adj.store(parent.oom_score_adj(), Ordering::Release);
        // PR_SET_TIMERSLACK state is inherited across fork and preserved by
        // exec, like Linux task_struct::timer_slack_ns.
        task.timer_slack_ns.store(parent.timer_slack_ns.load(Ordering::Acquire), Ordering::Release);
        // comm is inherited across fork/CLONE_THREAD exactly like Linux
        // copies task_struct::comm in dup_task_struct — a pthread_create'd
        // thread starts with the creator's name until it renames itself via
        // prctl(PR_SET_NAME)/pthread_setname_np.
        task.set_comm_bytes(parent.comm_bytes());
        // SUID_DUMP_* / THP_DISABLE are inherited across fork/clone (Linux
        // copies mm->flags).
        task.dumpable.store(parent.dumpable.load(Ordering::Acquire), Ordering::Release);
        task.thp_disable.store(parent.thp_disable.load(Ordering::Acquire), Ordering::Release);
        // Namespace publication runs after this allocation on both arches.
        static NEXT_VPID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(2);
        let v = NEXT_VPID.fetch_add(1, Ordering::AcqRel);
        task.vtgid.store(v, Ordering::Release);
        task.vtid.store(v, Ordering::Release);
        // Seccomp is INHERITED across fork/clone and PRESERVED across execve
        // (Linux copies the filter chain in dup_task_struct; execve never
        // clears it). Without this a seccomp-sandboxed process could fork() and
        // the child would run with an EMPTY filter set — a trivial sandbox
        // escape (`fork(); <forbidden syscall in child>`).
        // SAFETY: parent is the running task on this CPU (single-mutator read
        // per `13§5`); `task` is local and not yet scheduled (single-mutator
        // write). The child gets its own copy of the filter chain.
        unsafe { *task.seccomp_filters.get() = (*parent.seccomp_filters.get()).clone(); }
        // Landlock ruleset chain is likewise inherited across fork and kept
        // across execve — a Landlock-confined process's children stay confined.
        let parent_chain = parent.landlock_chain.lock().clone();
        *task.landlock_chain.lock() = parent_chain;
    }

    // SAFETY: task is local; no concurrent reader. install_stack allocates a
    // guard-paged kernel stack (Linux CONFIG_VMAP_STACK) and stores its top.
    if !unsafe { task.install_stack() } { return Err(SpawnError::NoMem); }
    let stack_top = task.kernel_stack.load(Ordering::Acquire);

    // SAFETY: stack_top freshly installed; entry_va/user_sp/regs from parent's saved frame; new_user_for_fork lays out the IRQ-epilogue frame for EL0 resume with regs preloaded.
    unsafe {
        let p = task.arch_ctx_ptr::<ArchCtx>();
        core::ptr::write(p, ArchCtx::new_user_for_fork(stack_top, entry_va, user_sp, regs));
    }

    let start_boottime_ns = monotonic_ns();
    task.start_boottime_ns = start_boottime_ns;
    let arc = Arc::new(task);
    arc.spawn_ns.store(start_boottime_ns, Ordering::Release);
    // The caller publishes only after every fallible clone step completes.
    Ok(arc)
}
