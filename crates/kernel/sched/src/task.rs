// Task descriptor manifest for the scheduler per `13§5`.
//
// Module map:
// - types: signal info, scheduling policy/class, task state.
// - creds: POSIX credentials and capability helpers.
// - dup: refcounted Task allocation (`dup_task_struct` shape) — construct into
//   the Arc, never onto the creator's kernel stack.
// - signals: sigaction storage plus mm/rlimit accessors.
// - arch: opaque arch context/FPU buffers and POSIX timer slot type.
// - methods: constructors, fd-table, stack, context, state, and pid helpers.
// - exe_path: pin-locked /proc/<pid>/exe path accessors (clone/with/set).
// - comm: spinlock-guarded TASK_COMM_LEN `comm` buffer accessors (`prctl`
//   PR_SET_NAME/PR_GET_NAME, procfs, diagnostics).
// - namespaces: atomic concrete namespace-set ownership and lifetime operations.
// - net_namespace: owned network-namespace membership slot operations.
// - fs_context: Linux-shaped shared root/pwd ownership and snapshots.
// - io_context: I/O priority context accessors + the effective-priority rule.
// - cap: Linux CAP_* constants.
// - restart: per-task `restart_block` for `restart_syscall(2)`.
// - uapi: TASK_COMM_LEN / SUID_DUMP_* constants.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI8, AtomicI32, AtomicPtr, AtomicU16, AtomicU32, AtomicU64, AtomicU8};
#[cfg(feature = "debug-task-fpu-provenance")]
use core::sync::atomic::AtomicUsize;

use sync::{Namespace, Spinlock, TaskList as TaskListClass};
use vfs::FdTable;
use vmm::AddressSpace;
use network_namespace::NetworkNamespaceRef;

mod arch;
pub mod cap;
mod comm;
pub mod dup;
pub(crate) mod creds;
mod exe_path;
mod parent_arc;
mod proc_strings;
mod rlimits;
mod fd_table;
mod fs_context;
mod io_context;
pub mod io_uring;
mod lifetime;
mod mempolicy;
mod methods;
mod net_namespace;
mod namespaces;
pub mod restart;
mod signals;
mod sigwake;
mod types;
mod uapi;

pub use arch::{ArchCtxBuf, ArchFpuBuf, PosixTimer};
pub use creds::{securebits, Creds, GroupList};
pub use fs_context::{FsContext, FsContextSnapshot, UMASK_MASK};
pub use io_context::current_ioprio;
pub use namespaces::TaskNamespaceSnapshot;
pub use restart::RestartBlock;
pub use signals::{SaHandler, SigActions, SignalPending, SA_IMMUTABLE, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK};
pub use sigwake::{SleepWake, WaitOutcome, WaitState, signal_pending_state};
pub use types::{SchedClass, SchedPolicy, SigInfo, TaskState, RT_QUEUE_CAP};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingWake { Drop, Ready, Defer }

pub use uapi::{MCE_KILL_EARLY, MCE_KILL_PROCESS, SUID_DUMP_DISABLE, SUID_DUMP_ROOT,
    SUID_DUMP_USER, TASK_COMM_LEN, THP_DISABLE_COMPLETELY, THP_DISABLE_EXCEPT_ADVISED,
    THP_DISABLE_OFF};

pub struct Task {
    #[cfg(feature = "debug-smp")]
    pub dbg_canary_head: AtomicU64,
    pub tid:  u32,
    /// Thread-group id per Linux clone(CLONE_THREAD) semantics —
    /// the leader's `tid` shared by every thread in the same
    /// process. `getpid()` returns this; `gettid()` returns `tid`.
    /// For non-CLONE_THREAD spawns (fork) `tgid == tid`.
    pub tgid: AtomicU32,
    /// Canonical PID identity, retained by pidfds after `release_task`.
    pub pid: Arc<crate::pid::PidIdentity>,
    /// Stable process thread-group owner.
    pub thread_group: Arc<crate::thread_group::ThreadGroup>,
    /// Linux `task_struct::comm` — mutable, NUL-padded, per-THREAD. Set at
    /// spawn/execve/fork-clone/`prctl(PR_SET_NAME)`; use `task/comm.rs`
    /// accessors, not this field directly (sole comm storage, `07§5`).
    pub name: Spinlock<[u8; TASK_COMM_LEN], TaskListClass>,

    pub state:    AtomicU8,
    pub on_rq:    AtomicBool,
    /// SMP `on_cpu` (Linux): true while executing on a CPU; set on switch-to,
    /// cleared in finish_task_switch after register save; remote ttwu spins on it.
    pub on_cpu:   AtomicBool,
    /// Linux `TIF_NEED_RESCHED` (`thread_info::flags`), per-TASK — never
    /// per-CPU. `__resched_curr` stamps the flag on
    /// `rq->curr`'s thread_info, and `__schedule` clears it on `prev`
    /// (`clear_tsk_need_resched(prev)`), so a tick that lands while THIS task
    /// is descheduled is charged to whoever was actually running. A per-CPU
    /// flag makes the resumed task inherit a request that was not its own —
    /// which the return-to-user work loop then re-services on every pass,
    /// re-scheduling immediately after being given the CPU (B1476).
    pub need_resched: AtomicBool,
    /// cgroup v2 freezer: held off every runqueue (enqueue no-op) until thawed.
    pub frozen:   AtomicBool,
    /// Linux `sched_yield`: consumed by `schedule()` before re-enqueueing current.
    pub yield_pending: AtomicBool,
    /// Linux `kthread_should_stop`: set by `kthread_stop`, polled by the thread's
    /// own loop. A kthread loop is `while !should_stop() { ... }`; nothing
    /// forcibly terminates it, because a kthread holding locks or mid-I/O must
    /// unwind itself.
    pub kthread_stop: AtomicBool,
    /// Linux `kthread_park`: the thread parks at its next check and stays
    /// parked until unparked. Used for CPU hotplug, where a per-CPU kthread
    /// must stand down without exiting.
    pub kthread_park: AtomicBool,
    /// Set by the thread once it has observed a park request and parked, so
    /// `kthread_park()` can wait for it to actually be off the CPU.
    pub kthread_parked: AtomicBool,
    /// Linux `PF_KTHREAD`: created as a kernel thread and has never run user
    /// code. Set by the kernel-thread spawn path, cleared the moment `execve`
    /// installs a user address space — the same split the reference draws
    /// between a kernel thread and a user-mode thread started from the kernel.
    pub kernel_thread: AtomicBool,
    /// Linux `kthread->result`: the value the thread handed to `kthread_exit`,
    /// which is what `kthread_stop` returns to the joiner.
    pub kthread_result: AtomicI32,
    /// Linux `kthread->exited` completion: published once the thread is off its
    /// own stack for good, so a joiner may drop the last reference safely.
    pub kthread_exited: AtomicBool,
    /// True once `wait4`/`waitid` has collected this task's exit status (Linux
    /// `release_task`). The Task may still be pinned alive by an open pidfd, but
    /// a reaped process MUST vanish from `/proc`: procfs enumeration
    /// (`live_vpids`/`live_tids`/`live_counts`) skips reaped tasks, so ps/htop
    /// never show a reaped-but-pidfd-pinned child as a lingering zombie.
    pub reaped:   AtomicBool,
    /// Set the moment the task enters its exit path, before its cgroup
    /// membership is torn down — the reference's `PF_EXITING`.
    ///
    /// A cgroup migration must refuse a task that is on its way out, or the
    /// migration races the teardown and resurrects membership for a task that
    /// is leaving. The reference tests this flag ON THE TASK; a side table
    /// keyed by tid was tried here instead, and it retained an entry for a
    /// LIVE task, so the service manager could not move its own pid into its
    /// own cgroup: `Failed to create /init.scope control group: No such
    /// process`, then `Freezing execution.` One fact, on the task that owns it.
    pub exiting:  AtomicBool,
    /// Linux `/proc/<pid>/oom_score_adj`, bounded by -1000..=1000.  It is
    /// task-owned rather than inferred from a cgroup or executable name.
    pub oom_score_adj: AtomicI32,
    /// One-way OOM exit claim.  It closes concurrent memcg OOM selection so
    /// a task already being fatally exited cannot be selected a second time.
    pub oom_victim: AtomicBool,
    /// Lockless wake-list linkage (Linux `task_struct.wake_entry`, an
    /// `llist_node`). Owned by whichever CPU's wake list currently holds this
    /// task; touched only between a successful `on_wake_list` claim and the
    /// drain that releases it, so no lock orders access to it.
    pub wake_next: AtomicPtr<Task>,
    /// Claim bit for the wake list: set by the pusher's compare-exchange,
    /// cleared by the drain. A second waker that loses the claim drops its
    /// reference instead of pushing — the enqueue it wanted is already pending,
    /// which is Linux's `llist_add` returning false. Without it a task pushed
    /// twice while still linked would overwrite its own `wake_next` and cycle
    /// the list.
    pub on_wake_list: AtomicBool,
    pub cpu:      AtomicU16,
    pub vruntime: AtomicU64,
    /// Monotonic ns this task last (re)started running; update_curr charges
    /// `now - exec_start` to runtime+vruntime then re-stamps. 0 = never-run.
    pub exec_start_ns: AtomicU64,
    /// Total CPU time (ns) consumed — /proc/<pid>/stat utime + cgroup cpu (`13§3`).
    pub sum_exec_runtime_ns: AtomicU64,
    /// Linux generic-vtime accounting boundary. While the task owns a CPU,
    /// this is the monotonic timestamp at which its current user/system
    /// interval began; zero means the task is off-CPU. Updated only by the
    /// running task's entry/exit path or its runqueue during a switch.
    pub vtime_start_ns: AtomicU64,
    /// Current generic-vtime mode (`cpustat::VTIME_{SYSTEM,USER}`). The mode
    /// survives a context switch; `vtime_start_ns` excludes the off-CPU gap.
    pub vtime_state: AtomicU8,
    pub last_syscall_nr: AtomicU32, // diag: last syscall nr entered (u32::MAX=none); stamped in diag::note_syscall
    pub nsyscalls: AtomicU64,        // diag: monotonic syscall-entry count (sysrq/watchdog dump)
    /// Linux `task_struct::min_flt` / `maj_flt` — page faults resolved without
    /// and with a backing-store read. Feed `/proc/<pid>/stat` fields 10/12 and
    /// `PERF_COUNT_SW_PAGE_FAULTS{,_MIN,_MAJ}`.
    pub min_flt: AtomicU64,
    pub maj_flt: AtomicU64,
    /// Linux `task_struct::nvcsw` / `nivcsw` — voluntary (blocked) and
    /// involuntary (preempted) context switches away from this task.
    /// `PERF_COUNT_SW_CONTEXT_SWITCHES` is their sum.
    pub nvcsw:  AtomicU64,
    pub nivcsw: AtomicU64,
    /// Linux `sched_entity::nr_migrations` — `PERF_COUNT_SW_CPU_MIGRATIONS`.
    pub nr_migrations: AtomicU64,
    #[cfg(feature = "debug-getdents")]
    pub(crate) getdents: crate::diag::getdents::GetdentsState,
    #[cfg(feature = "debug-syscall-return")]
    pub(crate) syscall_return: crate::diag::syscall_return::SyscallReturnState,
    /// Linux task I/O accounting (`/proc/<pid>/io`). `rchar/syscr` are charged
    /// by read-family syscalls; write-family lanes charge `wchar/syscw`.
    pub io_rchar: AtomicU64,
    pub io_wchar: AtomicU64,
    pub io_syscr: AtomicU64,
    pub io_syscw: AtomicU64,
    pub io_read_bytes: AtomicU64,
    pub io_write_bytes: AtomicU64,
    pub io_cancelled_write_bytes: AtomicU64,
    /// diag: user VA this task is parked on in a futex WAIT (0 = not waiting).
    /// Set under the WAITERS lock before schedule(), cleared on resume; the
    /// watchdog dump prints it so a wedge shows exactly which lock each task
    /// blocks on (and whether a holder exists).
    pub futex_uaddr: AtomicU64,
    /// Live CFS load weight (mutable, unlike the `SchedClass::Normal`
    /// seed). `update_curr` divides by this; `setpriority`/nice and
    /// cgroup `cpu.weight` rewrite it. Seeded from `class` at creation.
    pub load_weight: AtomicU32,
    /// Linux `task_struct::cpus_mask` — the EFFECTIVE CPU-affinity mask (bit N
    /// = may run on CPU N), composed from [`Self::user_cpus_allowed`] and
    /// [`Self::cpuset_cpus_allowed`]. Balancer, ttwu and initial placement all
    /// refuse to place outside it. Default all-ones; inherited on fork.
    pub cpus_allowed: AtomicU64,
    /// Linux `task_struct::user_cpus_ptr` — the mask `sched_setaffinity(2)`
    /// last requested, kept apart from the effective mask so a later cgroup
    /// `cpuset.cpus` change re-applies the user's request instead of erasing
    /// it. `0` = never set.
    pub user_cpus_allowed: AtomicU64,
    /// Linux `cpuset_cpus_allowed(p)` — the mask the task's cpuset permits.
    /// Default all-ones (no cpuset restriction).
    pub cpuset_cpus_allowed: AtomicU64,
    /// Linux `PF_NO_SETAFFINITY` — set on per-CPU kernel threads
    /// (`ksoftirqd/N`, `kworker/N`) that `kthread_bind` pinned; their affinity
    /// is structural, so `sched_setaffinity(2)` on them is EINVAL.
    pub no_setaffinity: AtomicBool,
    /// Encoded `SchedClass` (lock-free; read via `sched_class()`, mutated via
    /// `set_sched_class()` so sched_setattr/setparam can change policy at runtime).
    pub class_enc: AtomicU64,
    /// Linux `task_struct::policy` — the SCHED_* code userspace set, stored
    /// separately from `class_enc` exactly as Linux stores `p->policy` apart
    /// from `p->sched_class`. Required because several policies share one
    /// implementation class (`SCHED_NORMAL`/`SCHED_BATCH`/`SCHED_IDLE` all run
    /// on CFS), so the class alone cannot round-trip through
    /// `sched_getscheduler(2)` / `sched_getattr(2)` / `/proc/<pid>/stat`.
    pub policy: AtomicU32,
    /// Linux `sched_rt_entity::time_slice` — remaining ticks of this `SCHED_RR`
    /// task's quantum. `SCHED_FIFO` never consumes it (FIFO has no timeslice);
    /// the fair class does not use it either.
    pub rt_time_slice: AtomicU32,

    /// Pending "requeue to the tail" request for a real-time task, set when it
    /// gives up its turn — a spent `SCHED_RR` quantum or an explicit
    /// `sched_yield` — and consumed by `put_prev_task`. Absent it, a preempted
    /// task rejoins its priority queue at the HEAD, which is what makes
    /// `SCHED_FIFO` differ from `SCHED_RR` at all.
    pub rt_requeue_tail: AtomicBool,
    /// `SCHED_DEADLINE` reservation + instance state (`deadline::DlEntity`).
    /// Present on every task and inert until a deadline policy is admitted, so
    /// the class's ordering key is readable from any task without a branch.
    pub dl: crate::deadline::DlEntity,
    /// Linux `task_struct::mempolicy` — the PER-THREAD NUMA policy
    /// `set_mempolicy(2)` installed, packed by `MemPolicy::to_words`. Word 0
    /// is zero when no policy is installed, which is Linux's NULL
    /// `->mempolicy` (i.e. MPOL_DEFAULT). Inherited by fork/clone
    /// (Linux `mpol_dup`) and NOT reset by execve.
    /// Read/written through `mempolicy()` / `set_mempolicy()`.
    pub mempolicy: [AtomicU64; 3],
    /// Linux `task_struct::sched_reset_on_fork`. Set by the
    /// `SCHED_RESET_ON_FORK` bit ORed into the `sched_setscheduler(2)` policy
    /// argument; ORed back into `sched_getscheduler(2)`'s return; consumed by
    /// the fork path, which drops an RT/DEADLINE child back to `SCHED_NORMAL`
    /// nice 0 and then clears the flag on the child.
    pub sched_reset_on_fork: AtomicBool,
    /// Linux `task_struct::se.slice` — the CFS slice `sched_setattr(2)` sets
    /// from `sched_attr::sched_runtime` and `sched_getattr(2)` reports back.
    /// `0` is Linux's `!se.custom_slice`, which reads back as
    /// `sysctl_sched_base_slice`. Inherited on fork.
    pub sched_slice_ns: AtomicU64,
    /// Linux `task_struct::uclamp_req[UCLAMP_MIN]` / `[UCLAMP_MAX]` values —
    /// the per-task utilization-clamp request `sched_setattr(2)`'s
    /// `SCHED_FLAG_UTIL_CLAMP_{MIN,MAX}` sets and `sched_getattr(2)` reports.
    pub uclamp_min: AtomicU32,
    pub uclamp_max: AtomicU32,
    /// `uclamp_se::user_defined` for both clamps — bit0 = MIN, bit1 = MAX.
    /// A clamp that was never requested by userspace is reset to its class
    /// default on every `sched_setattr`; a user-defined one survives.
    pub uclamp_user_defined: AtomicU8,

    pub exit_status: AtomicI32,
    /// Low-byte clone/fork exit signal (`task_struct::exit_signal`). Linux
    /// wait selectors use this to distinguish normal SIGCHLD children from
    /// clone children for `__WCLONE`/`__WALL`.
    pub exit_signal: AtomicU8,

    /// Parent TID per `13§5` / `15§5`. Set by `sys_fork` when the
    /// child Task is constructed; `0` for tasks with no parent
    /// (boot-anchor idle, kthreads spawned at boot). Read by
    /// `wait4` to find Zombie children of the current task.
    pub parent_tid: AtomicU32,

    /// Linux `PF_FORKNOEXEC`: set for every newly forked task, cleared by the
    /// first successful `execve`. `setpgid(2)` reads it on a CHILD target —
    /// a parent may only reparent a child that has not yet exec'd (EACCES
    /// otherwise), which is what lets a shell set up a job's process group
    /// exactly once, in the window between fork and exec.
    pub forknoexec: AtomicBool,

    /// Linux `PF_NPROC_EXCEEDED`: armed by a `set*uid` that moved this task
    /// into an account already at its `RLIMIT_NPROC`, and consumed by the
    /// next `execve(2)`, which then fails EAGAIN. The failure is deferred to
    /// exec rather than reported by `setuid` because too much software
    /// ignores `setuid`'s return value — a silent success there would hand
    /// the caller the identity without the quota.
    pub nproc_exceeded: AtomicBool,

    /// Whether this task currently holds a `RLIMIT_NPROC` charge against
    /// [`Self::ucounts_ns`]/[`Self::ucounts_uid`]. Latched so a task that
    /// reaches its terminal state twice releases its charge exactly once —
    /// an over-release would hand the account permanent free capacity.
    pub nproc_charged: AtomicBool,

    /// The user namespace half of the account this task's `RLIMIT_NPROC`
    /// charge sits in (Linux `cred->ucounts->ns`). Latched at charge time,
    /// not recomputed at release: namespace membership is dropped before a
    /// task reaches its terminal state, so a recomputed key would release
    /// the charge against the wrong account and leak the real one.
    pub ucounts_ns: AtomicU64,

    /// The uid half of that account (Linux `cred->ucounts->uid`) — the REAL
    /// uid, which is the id `RLIMIT_NPROC` is accounted against.
    pub ucounts_uid: AtomicU32,

    /// Linux `PF_SUPERPRIV`: latched the first time a capability check on this
    /// task SUCCEEDS (`capable()` sets it on the allow path only). BSD process
    /// accounting reports it as the `ASU` record flag — "used super-user
    /// privileges" — which is a statement about what the task DID, not about
    /// what it was allowed to do, so it cannot be derived from the credentials
    /// at exit.
    pub used_superpriv: AtomicBool,

    /// Top of kernel stack (one-past-end). AtomicPtr; read-only on hot.
    pub kernel_stack: AtomicPtr<u8>,

    /// Memcg that owned the kernel-stack allocation at creation. A task move
    /// never transfers this charge; final Task release does.
    pub kernel_stack_memcg: AtomicU64,
    /// Exact charged byte extent, retained with the Box for final release.
    pub kernel_stack_charge_bytes: AtomicU64,

    /// Backing storage for the kernel stack — allocated by the
    /// spawn path, freed when the `Arc<Task>` drops. `None` for
    /// tasks that don't own a stack (idle, boot frame, hosted tests
    /// constructing Tasks for runqueue logic only). The pointer
    /// in `kernel_stack` aliases `stack[stack.len()]` (one past
    /// the last byte = top-of-stack on x86_64 / aarch64).
    pub stack: Option<crate::kstack::GuardedStack>,

    /// Opaque per-arch HAL `Context` (per `14§5.2`/`14§6.2`). Sized
    /// to `ARCH_CTX_SIZE`; aligned for the arch-specific Context's
    /// first field. Access gated by the runqueue invariant.
    pub arch_ctx: UnsafeCell<ArchCtxBuf>,

    /// Per-task user address space per `13§5` / `11§3`. `None` for
    /// kthreads. `Arc`-shared so `CLONE_VM` siblings share the
    /// VMA tree; `execve` replaces in-place under the single-
    /// mutator-per-CPU invariant.
    pub mm: UnsafeCell<Option<Arc<AddressSpace>>>,
    /// Serializes an external `Arc` pin against exec/exit's in-place mm
    /// replacement. Normal current-task paths retain the single-mutator
    /// contract; cross-task observers must use `clone_mm` rather than
    /// borrowing this UnsafeCell directly.
    pub mm_pin_lock: Spinlock<(), TaskListClass>,

    /// Per-task open-file table per `13§5` / `16§3`. `None` for
    /// tasks that don't carry one (kthreads, the boot-anchor
    /// idle). Shared via `Arc` per `clone3` semantics: `CLONE_FILES`
    /// siblings share the same table; default fork copies entries
    /// (v1: shares the Arc, deferring per-entry copy until needed).
    /// Wrapped in `UnsafeCell` for `dup2` / `close` / `execve`
    /// (CLOEXEC) — single-mutator-per-active-CPU invariant.
    pub fd_table: UnsafeCell<Option<Arc<FdTable>>>,
    /// Serializes an external `Arc` pin against exit's in-place fd_table
    /// clear (`replace_fd_table(None)`), mirroring `mm_pin_lock` above.
    /// Normal current-task paths retain the single-mutator contract;
    /// cross-task observers (kcmp, pidfd_getfd, /proc/<pid>/fd*) must use
    /// `clone_fd_table` rather than borrowing this UnsafeCell directly —
    /// otherwise a concurrent exit on another CPU can drop the last
    /// `Arc<FdTable>` strong ref mid-read (UAF).
    pub fd_table_pin_lock: Spinlock<(), TaskListClass>,
    /// Linux `task_struct::io_uring`: the per-task io_uring context, holding
    /// the ring descriptors this task registered by INDEX rather than by fd so
    /// a submission can name one without an fd-table lookup. A pointer, not an
    /// inline array, and allocated on first registration exactly as the
    /// reference allocates its context on first use — most tasks never open a
    /// ring and must not pay for the slots. Dropped at exit and at `execve`.
    pub registered_rings: Spinlock<Option<alloc::boxed::Box<io_uring::RegisteredRings>>,
        TaskListClass>,

    /// Pending signal bitmap per `27§3` (Linux kernel_sigset_t = 64
    /// bits). Bit i set ⇔ signal i+1 pending. Updated atomically by
    /// `kill`/`tgkill` from any CPU; checked at syscall return per
    /// `27§5` ("signals delivered on transition to user mode").
    /// # C: O(1)
    pub sigpending: SignalPending,

    /// Per-signal siginfo_t queue — Linux `struct sigpending::list`, kept as
    /// one bounded queue per signal number (64 slots indexed by `sig - 1`, see
    /// `signum::sigq_index`). RT signals (33..=64) preserve multiplicity per
    /// POSIX: every `sigqueue(SIGRTn, val)` enqueues a distinct
    /// (signo,val,pid,uid,code) record, bounded by the per-user
    /// `RLIMIT_SIGPENDING` count each record carries. Standard
    /// signals collapse to ONE record (Linux `legacy_queue`) but still carry
    /// it — `sigqueue(3)`/`timer_create(2)`/`tgkill(2)` set si_code/si_value
    /// for them, and handlers (glibc SIGCANCEL/SIGSETXID) test those fields.
    /// SIGCHLD uses this table like every other standard signal; a
    /// child-exit record is queued on the PROCESS' shared set by
    /// `do_notify_parent`, so any thread can collect it.
    /// # C: O(1) push / O(1) pop
    pub sigqueue: Spinlock<[VecDeque<crate::sigqueue::Queued>; 64], TaskListClass>,

    /// Per-task signal mask per `27§3`. Bit i set ⇔ signal i+1
    /// blocked. `rt_sigprocmask` writes; signal-delivery checks.
    /// # C: O(1)
    pub sigmask: AtomicU64,

    /// Linux `task_struct::saved_sigmask` + `TIF_RESTORE_SIGMASK`.
    /// `rt_sigsuspend`/`pselect6`/`ppoll` install a temporary mask and must
    /// NOT put the old one back before returning: a handler that fires on the
    /// way out has to run under the TEMPORARY mask, and `rt_sigreturn` then
    /// restores the saved one from the signal frame. Restoring eagerly at
    /// syscall exit runs the handler with the wrong mask — the exact race
    /// `sigsuspend(2)` exists to close. `restore_sigmask` is the armed flag;
    /// consumed by signal delivery (folded into the frame) or by the
    /// syscall-return tail when no handler runs. See `Task::arm_saved_sigmask`.
    /// # C: O(1)
    pub saved_sigmask:   AtomicU64,
    pub restore_sigmask: core::sync::atomic::AtomicBool,

    /// Per-task alternate signal stack, set by `sigaltstack(2)`.
    /// `sigaltstack_sp` is the user VA of the stack base, `_size`
    /// is its byte length, `_flags` is SS_AUTODISARM / SS_DISABLE
    /// per Linux. `sig_dispatch` reads these when an action with
    /// SA_ONSTACK fires to pick the alternate stack.
    /// # C: O(1)
    pub sigaltstack_sp:    AtomicU64,
    pub sigaltstack_size:  AtomicU64,
    pub sigaltstack_flags: AtomicU32,

    /// Linux `sighand_struct`: shared by CLONE_SIGHAND siblings, deep-copied by fork.
    pub sigactions: UnsafeCell<Arc<SigActions>>,

    /// Weak-ref to parent Task per `27§5` SIGCHLD delivery. Set by
    /// `sys_fork` at construction (unpublished, safe). UNLIKE `mm`/
    /// `fd_table`, this is ALSO rewritten later by a foreign task: an
    /// exiting parent's `reparent_children`/`reap_orphans` (`sched/src/
    /// live/zombies/reparent.rs`) writes a LIVE child's `parent_arc` from
    /// the parent's own CPU while that child may be running on another
    /// CPU right now — the previous doc comment's "same single-mutator
    /// invariant as mm" claim was wrong for this field specifically (and
    /// was found wrong for `mm` itself too, B1326). `Spinlock`-protected;
    /// use `Task::parent()`/`parent_weak()`/`set_parent_weak()`, never a
    /// raw borrow.
    pub parent_arc: Spinlock<Option<Weak<Task>>, TaskListClass>,

    /// User-side argv string per `19§4` for `/proc/<pid>/cmdline`. Set at
    /// `sys_execve` time to a NUL-separated copy of argv; `None` for tasks
    /// without an execve (boot's init-anchor uses `task.name` as a
    /// fallback). Spinlock-protected like `exe_path`/`parent_arc`: read
    /// for an arbitrary foreign pid via `/proc/<pid>/cmdline`
    /// (`procfs/src/live/pid_files.rs`) with no synchronization against a
    /// concurrent `execve` writer on that task's own CPU otherwise — same
    /// torn-`String`-read UAF shape as `exe_path` (B1326/B1329).
    pub cmdline: Spinlock<Option<alloc::string::String>, TaskListClass>,

    /// Absolute path passed to the most recent `sys_execve(path,…)`,
    /// per Linux `/proc/<pid>/exe`. Distinct from `cmdline` (which
    /// stores argv[0..]; argv[0] is conventionally the basename
    /// the program was invoked as, not its filesystem path).
    /// Programs readlink `/proc/self/exe` to discover their
    /// own binary path; without the real exec path here, multi-call
    /// binaries misbehave. Spinlock-guarded (not the `UnsafeCell`
    /// single-mutator pattern used elsewhere in this struct): unlike
    /// `cmdline`/`mm`/`fd_table`, `exe_path` is read from many foreign-CPU
    /// call sites (timer-IRQ deadline scan, procfs, ptrace, tracing) that
    /// have no synchronization against a concurrent `execve` writer on this
    /// task's own CPU. `String`'s `(ptr,len,cap)` representation is not
    /// atomically readable, so an unsynchronized foreign read during a
    /// writer's in-place assignment is a torn-read UAF (out-of-bounds read
    /// via a partial pointer/len pair). Mirrors `mm_pin_lock`/
    /// `fd_table_pin_lock` precedent, folded directly into the field
    /// instead of a side pin-lock since every access already goes through
    /// `task/exe_path.rs` accessors.
    pub exe_path: Spinlock<Option<alloc::string::String>, TaskListClass>,
    /// Linux `mm_struct::exe_file`. Retained so the running image holds a
    /// `deny_write_access` on its inode for as long as it is executing —
    /// modern Linux dropped `VM_DENYWRITE` and hangs `ETXTBSY` off the
    /// exe_file instead (`exe_file_deny_write_access`,
    /// `replace_mm_exe_file`). Without it, a running binary's
    /// text can be rewritten under it.
    pub exe_inode: Spinlock<Option<vfs::InodeRef>, TaskListClass>,

    /// Linux `fs_struct` analogue: shared by `CLONE_FS` tasks and replaced by
    /// `unshare(CLONE_FS)`.  Private so readers/writers must use owned
    /// snapshots and cannot race pivot-root's remote update.
    fs_context: Spinlock<Arc<FsContext>, TaskListClass>,

    /// User-side envp string per `19§4` for `/proc/<pid>/environ`.
    /// NUL-separated copy of `envp[0..envc]`, written at execve time.
    /// Spinlock-protected — same foreign-pid-read rationale as `cmdline`.
    pub environ: Spinlock<Option<alloc::string::String>, TaskListClass>,

    /// Per-task nice value per POSIX nice(2)/setpriority(2). Range
    /// nice [-20, 19]; 0 default; inherited on fork. Scheduler
    /// ignores (CFS weight fixed); stored for getpriority /
    /// /proc/<pid>/stat field 19.
    pub nice: AtomicI8,

    /// I/O priority context. Holds the RAW `int` `ioprio_set(2)` stored, which
    /// `ioprio_get(IOPRIO_WHO_PROCESS)` reports verbatim so userspace can tell
    /// "never set" from an explicit value; the effective priority derives
    /// class and level from nice whenever the stored class is unset.
    ///
    /// A shared object rather than a field because `CLONE_IO` makes the child
    /// share the parent's, so a later `ioprio_set` on either is seen by both.
    /// The pointer is guarded because the clone path installs the shared
    /// context after the child task already exists; reach it through
    /// `Task::io_context()` / `Task::set_io_context()`.
    pub(crate) io_context: Spinlock<alloc::sync::Arc<crate::ioprio::IoContext>, TaskListClass>,

    /// Monotonic ns at spawn; getrusage/times/proc-stat utime
    /// derived as `monotonic_ns() - spawn_ns`. 0 in hosted tests.
    pub spawn_ns: AtomicU64,
    /// Host CLOCK_BOOTTIME ns at task creation; proc stat field 22 applies
    /// the reader's TIME namespace offset before conversion to clock ticks.
    pub start_boottime_ns: u64,
    /// F169 WaitList::park_with_deadline; 0 = indefinite.
    pub wakeup_deadline_ns: AtomicU64,
    /// Per-task user-mode CPU time (ns), tick-sampled at the timer IRQ
    /// (Linux CONFIG_TICK_CPU_ACCOUNTING); read by getrusage/times/proc-stat.
    pub utime_ns: AtomicU64,
    /// Per-task kernel-mode CPU time (ns), tick-sampled at the timer IRQ
    /// (Linux CONFIG_TICK_CPU_ACCOUNTING); read by getrusage/times/proc-stat.
    pub stime_ns: AtomicU64,
    // Reaped children's accumulated resource use is PROCESS-wide state and
    // lives on `ThreadGroup` (`thread_group::child_acct`), like `rlimits` and
    // `pgid` — any thread may reap, and every sibling must see the result.

    /// alarm(2)/setitimer ITIMER_REAL deadline in monotonic ns.
    /// `0` = no alarm pending. Dispatch tail compares against
    /// monotonic_ns() and posts SIGALRM (signal 14) when reached.
    pub alarm_ns: AtomicU64,

    /// ITIMER_REAL period in ns. `0` = one-shot. When the deadline
    /// fires, dispatch tail re-arms `alarm_ns = now + interval` if
    /// non-zero. setitimer(0) sets; getitimer(0) reads.
    pub alarm_interval_ns: AtomicU64,
    /// ITIMER_VIRTUAL absolute user-CPU deadline in `utime_ns`.
    /// `0` = disarmed. Expiry posts SIGVTALRM.
    pub itimer_virtual_ns: AtomicU64,
    /// ITIMER_VIRTUAL period in user-CPU ns. `0` = one-shot.
    pub itimer_virtual_interval_ns: AtomicU64,
    /// ITIMER_PROF absolute CPU deadline in `utime_ns + stime_ns`.
    /// `0` = disarmed. Expiry posts SIGPROF.
    pub itimer_prof_ns: AtomicU64,
    /// ITIMER_PROF period in combined CPU ns. `0` = one-shot.
    pub itimer_prof_interval_ns: AtomicU64,
    /// Linux `sched_rt_entity::timeout`, the quantity `RLIMIT_RTTIME` bounds:
    /// CPU time charged to this thread while it ran under a real-time policy.
    /// Linux counts whole ticks and converts with `USEC_PER_SEC / HZ`; this
    /// kernel's tick period is not fixed, so the charged nanoseconds are
    /// accumulated directly and the µs conversion is exact.
    ///
    /// Cumulative, exactly as Linux is: it is zeroed at fork and when the task
    /// leaves a real-time policy, and NOT when the thread blocks.
    pub rt_timeout_ns: AtomicU64,

    /// CLONE_CHILD_CLEARTID address per set_tid_address(2). Linux stores the
    /// user pointer and, on thread exit (`do_exit` → `mm_release`), writes 0
    /// there and FUTEX_WAKE_PRIVATEs one waiter — `060_exit.rs` does both.
    /// pthread_join is served entirely by that wake.
    pub clear_child_tid: AtomicU64,

    /// `CLONE_CHILD_SETTID` address, when the write could not be done by the
    /// creator. A `CLONE_VM` child shares the creator's page tables, so the
    /// creator stores the tid directly; a forked child's copy of that page
    /// lives behind its own page-table root, so the address is parked here and
    /// the CHILD performs the store at its first return to user mode — where
    /// the copy-on-write fault resolves in the address space that owns it.
    /// Taken exactly once, mirroring Linux's fork-return-only write.
    pub set_child_tid: AtomicU64,

    /// Linux `task_struct::restart_block` — the continuation
    /// `restart_syscall(2)` resumes through after ERESTART_RESTARTBLOCK.
    pub restart_block: restart::RestartBlock,

    /// CLONE_VFORK rendezvous flag (mirrors Linux mm_struct::
    /// vfork_done): parent busy-yields until child clears via
    /// execve/exit. Without this, parent + child race on the
    /// shared CLONE_VM address space.
    /// 0 = not vfork-tracked or already-cleared (default);
    /// 1 = parent waiting on this child.
    pub vfork_pending: AtomicBool,

    /// Concrete non-network namespace owners. `None` after task exit, even
    /// while process identity or a pidfd retains this Task allocation.
    namespaces: Spinlock<Option<namespaces::TaskNamespaces>, Namespace>,

    /// Tracer tid for `ptrace(2)` — 0 = no tracer attached.
    /// PTRACE_TRACEME / ATTACH / SEIZE / DETACH / CONT / SYSCALL /
    /// SINGLESTEP / PEEK / POKE / GETREGS / SETREGS all wired
    /// against this field; debugger-frontend integration (gdbserver
    /// stub talking over a remote-protocol socket) is a follow-up.
    pub traced_by: AtomicU32,

    /// PTRACE_SETOPTIONS bit-set (PTRACE_O_TRACESYSGOOD/FORK/VFORK/
    /// CLONE/EXEC/VFORKDONE/EXIT/SECCOMP/EXITKILL). Stop-delivery
    /// path consults to set SIGTRAP|0x80 and fan fork-family events.
    pub ptrace_options: AtomicU32,
    /// PTRACE_GETEVENTMSG payload (e.g. child pid on FORK).
    pub ptrace_eventmsg: AtomicU64,
    /// siginfo_t snapshot at the most recent ptrace stop. Tracer
    /// reads via PTRACE_GETSIGINFO; writes via SETSIGINFO.
    pub ptrace_siginfo: Spinlock<Option<SigInfo>, TaskListClass>,

    /// Enforced Landlock domain. `landlock_restrict_self` replaces it with a
    /// strictly deeper one; path, port and scoped-IPC operations consult it.
    /// `None` means unconfined. It is never removed or narrowed in place — the
    /// domain object is immutable, so a live check can never observe a policy
    /// being widened underneath it.
    pub landlock_domain: Spinlock<Option<alloc::sync::Arc<landlock::Domain>>, TaskListClass>,
    /// Linux `task_struct::task_works` subset used by Landlock TSYNC.  The
    /// target thread takes and executes this work on its own return-to-user
    /// path; a foreign CPU never writes that thread's credentials directly.
    pub landlock_tsync_work:
        Spinlock<Option<alloc::sync::Arc<crate::landlock_tsync::Transaction>>, TaskListClass>,
    /// Transaction generation already enrolled on this task.  It remains
    /// stamped after the work starts so the initiator's repeated thread-group
    /// scans cannot enqueue the same task twice.
    pub landlock_tsync_id: AtomicU64,
    /// Linux `TIF_NOTIFY_SIGNAL`: not a real signal, but it breaks
    /// interruptible waits and forces the shared return-to-user work loop.
    pub notify_signal: AtomicBool,
    /// Per-arch FPU/SIMD snapshot for PTRACE_GETFPREGS/SETFPREGS.
    pub fpu_state: UnsafeCell<ArchFpuBuf>,
    /// Immutable construction-time raw FP/SIMD-area address. Diagnostic-only:
    /// it detects an interior Task overwrite before an asm save/restore uses
    /// the corrupted Box pointer.
    #[cfg(feature = "debug-task-fpu-provenance")]
    pub dbg_fpu_state_expected: AtomicUsize,
    /// Set by PTRACE_SETFPREGS; cleared by resume tail.
    pub ptrace_fpu_dirty: AtomicBool,

    /// PTRACE_SINGLESTEP arm bit (RFLAGS.TF x86; MDSCR_EL1.SS+SPSR.SS arm).
    pub singlestep: AtomicU32,

    /// Linux `TIF_NOCPUID` — `arch_prctl(ARCH_SET_CPUID, 0)` armed user-mode
    /// `cpuid` faulting for this thread. Per-THREAD, not per-CPU: the switch
    /// path programs the vendor MSR whenever the incoming task's bit differs
    /// from the outgoing one, exactly as `__switch_to_xtra` does. Inherited
    /// across fork, cleared at exec (`arch_setup_new_exec`).
    pub nocpuid: AtomicBool,

    /// This thread's aarch64 POR_EL0 snapshot. x86 PKRU belongs to the xstate
    /// image, which is saved and restored with every other x86 user register.
    ///
    /// Per-THREAD, and writable from user mode by an unprivileged `WRPKRU`, so
    /// this field is a SNAPSHOT the switch path refreshes by reading the live
    /// register on the way out; it is never treated as authoritative while the
    /// thread is running. Cleared to the restrictive default at exec, and
    /// inherited across fork so a thread that opened a key keeps it.
    ///
    /// POR_EL0 is 64 bits of 4-bit fields. Meaningless where that register
    /// does not exist.
    #[cfg(target_arch = "aarch64")]
    pub pkey_rights: AtomicU64,

    /// Linux `thread.features` / `thread.features_locked` — the CET
    /// shadow-stack facilities (`ARCH_SHSTK_SHSTK`, `ARCH_SHSTK_WRSS`) this
    /// thread has enabled, and those whose state may no longer change.
    /// `ARCH_SHSTK_STATUS` reports the first; `ARCH_SHSTK_LOCK` sets the
    /// second. Both reset at exec (`reset_thread_features`).
    pub shstk_features: AtomicU64,
    pub shstk_locked: AtomicU64,
    /// F206 aarch64 per-task SVC-frame ptr; deliver_arm reads here.
    #[cfg(target_arch = "aarch64")]
    pub svc_frame: core::sync::atomic::AtomicU64,
    /// Per-task seccomp cBPF chain per `13§5`. Drop on task exit.
    ///
    /// LOCKED, not `UnsafeCell`: `SECCOMP_FILTER_FLAG_TSYNC` publishes the
    /// caller's chain into every SIBLING thread (Linux `seccomp_sync_threads`
    /// under `siglock`), so the owning task is not the only writer and a
    /// bare cell would let a sibling's `Vec` realloc race the owner's
    /// per-syscall walk of it.
    pub seccomp_filters: Spinlock<alloc::vec::Vec<crate::seccomp_filter::SeccompFilter>, TaskListClass>,

    /// Linux `task_struct::seccomp.mode` — `SECCOMP_MODE_{DISABLED,STRICT,
    /// FILTER,DEAD}`. `prctl(PR_GET_SECCOMP)` returns it verbatim, so STRICT
    /// must be distinguishable from FILTER; deriving the answer from
    /// `seccomp_filters.len()` cannot do that, since a STRICT task has an
    /// EMPTY chain (Linux mode 1 installs no cBPF program at all) and so
    /// looks identical to an unconfined one.
    pub seccomp_mode: AtomicU8,

    /// Per-thread robust-mutex list head + len per
    /// `set_robust_list(2)` (slot 273) and Linux `struct robust_list_head`.
    /// glibc/musl pass a thread-local pointer at startup; on thread
    /// exit the kernel walks the list and wakes contending futexes
    /// (substrate for that walk rides a follow-up). Storing real
    /// values means `get_robust_list` returns what userspace set.
    pub robust_list_head: AtomicU64,
    pub robust_list_len:  AtomicU64,

    /// Linux `task_struct::sysvsem.undo_list` — this task's handle on the
    /// refcounted SysV `SEM_UNDO` adjustment list, 0 when it has none.
    ///
    /// PER-TASK and shared by handle, because that is exactly what
    /// `CLONE_SYSVSEM` shares: the flag is independent of `CLONE_THREAD`, so a
    /// plain `fork()` child starts with none while a `clone(CLONE_SYSVSEM)`
    /// child WITHOUT `CLONE_THREAD` shares its parent's list. Keying the list
    /// on the thread-group id instead reproduced only the two combinations
    /// glibc happens to issue. The list, its refcount and its entries belong to
    /// the SysV semaphore code; `sched` owns only this handle, since the handle
    /// is a property of the task and `ipc` is the crate that depends on this one.
    pub sysvsem_undo: AtomicU64,

    /// The scheduling class this task would run at with no PI boost in effect
    /// — its own, un-inherited class. `u64::MAX` means "not boosted"; any other
    /// value is an encoded [`crate::SchedClass`] saved by `live::pi_boost` when
    /// a PI-mutex waiter first lent this task its priority.
    ///
    /// Kept separate from `class_enc` because `class_enc` is BOTH the static
    /// and the effective priority: overwriting it to boost would otherwise
    /// destroy the base class, and the deboost at unlock would have nothing to
    /// restore to. A concurrent `sched_setscheduler` on a boosted task writes
    /// through to this field rather than to `class_enc`, so the new base takes
    /// effect at deboost instead of being clobbered by it.
    pub pi_base_class: AtomicU64,

    /// Saved `preempt_count` while this task is NOT running (Linux keeps it in
    /// `thread_info`; x86 caches it per-CPU and swaps it in `__switch_to`, which
    /// is the model used here).
    ///
    /// It must be per-task or the fields leak between tasks: anything that parks
    /// inside `do_softirq` — between the `SOFTIRQ_OFFSET` add and its matching
    /// sub — left the softirq field set for whatever ran next on that CPU.
    /// `in_interrupt()` then reported true there forever, so that CPU silently
    /// stopped draining softirqs and stopped rescheduling, and the eventual
    /// `preempt_count_sub` underflowed. Measured as an idle CPU pinned at
    /// `preempt_count=0x00010000` with nothing runnable.
    ///
    /// Live value lives in the per-CPU slot while the task runs; `schedule()`
    /// saves it here on switch-out and restores the incoming task's on
    /// switch-in.
    pub preempt_count: AtomicU32,

    /// Linux `PR_SET_NO_NEW_PRIVS` flag. Once set, the task and its
    /// descendants can no longer gain privileges via setuid binaries
    /// or capability-conferring file caps. Sticky: clearing is not
    /// allowed by Linux; we mirror that.
    pub no_new_privs: AtomicBool,

    /// Linux `TIF_NOTSC` (`prctl(PR_SET_TSC, PR_TSC_SIGSEGV)`) — this task
    /// may not read the time-stamp counter. Per-THREAD, not per-process.
    /// Consumed by the x86_64 arm of `schedule()`, which drives `CR4.TSD`
    /// from it on every switch so a trapped `rdtsc` raises `#GP` and the
    /// user-fault path turns that into SIGSEGV. Inherited across fork and
    /// preserved by execve (`flush_thread` does not clear the flag).
    /// aarch64 has no equivalent control; the option is x86-only there.
    pub tsc_sigsegv: AtomicBool,

    /// Linux arm64 `TIF_TAGGED_ADDR` (`prctl(PR_SET_TAGGED_ADDR_CTRL,
    /// PR_TAGGED_ADDR_ENABLE)`) — this task's user pointers may carry a
    /// non-zero top byte. Consumed by the aarch64 user-pointer validator,
    /// which strips the tag before the range check exactly as Linux's
    /// `access_ok` calls `untagged_addr`. Per-THREAD, inherited across fork,
    /// and cleared by execve.
    pub tagged_addr: AtomicBool,

    /// Linux `mm->flags SUID_DUMP_*` (`prctl(PR_SET_DUMPABLE/GET_DUMPABLE)`):
    /// DISABLE(0)/USER(1)/ROOT(2). Gates core dumps, ptrace, `/proc/pid/mem`
    /// ownership. Per-task (v1: mm not yet shared cross-thread, so no
    /// observable gap vs Linux's per-mm flag).
    pub dumpable: AtomicU8,

    /// `PR_SET_THP_DISABLE`/`GET_THP_DISABLE` — Linux's two `mm` flags
    /// `MMF_DISABLE_THP_COMPLETELY` / `MMF_DISABLE_THP_EXCEPT_ADVISED`,
    /// encoded as `THP_DISABLE_*` here because they are mutually exclusive.
    /// Inert by construction, not by omission: there is no transparent-huge-
    /// page allocator or collapse path in this kernel for the flag to gate,
    /// the same position as a Linux built without huge-page support, where the
    /// prctl still round-trips. Its consumer belongs next to the
    /// `thp_vma_allowable_order` equivalent when that path lands, with
    /// `/proc/<pid>/smaps` deriving `THPeligible` from it rather than
    /// hard-coding 0.
    pub thp_disable: AtomicU8,

    /// Per-task timer-slack value in nanoseconds, controlled by
    /// `prctl(PR_SET_TIMERSLACK)`. Linux `task_struct::timer_slack_ns`.
    pub timer_slack_ns: AtomicU64,

    /// Linux `task_struct::default_timer_slack_ns` — what
    /// `prctl(PR_SET_TIMERSLACK, 0)` restores. Inherited across fork, so a
    /// thread spawned by a low-latency parent keeps that parent's floor
    /// instead of snapping back to the 50us system default.
    pub default_timer_slack_ns: AtomicU64,

    /// Linux `PF_MCE_PROCESS` | `PF_MCE_EARLY` (`prctl(PR_MCE_KILL)`),
    /// packed as `MCE_KILL_PROCESS` / `MCE_KILL_EARLY`. Consumed by
    /// `memory_failure`'s early-kill decision upstream; there is no machine-
    /// check or hwpoison subsystem here, so nothing reads it yet and its
    /// consumer belongs with the poison bookkeeping when that lands.
    pub mce_kill: AtomicU8,

    /// `PR_SET_PDEATHSIG` — signal delivered to this task when its
    /// parent exits. `0` means "no signal". Cleared by execve when
    /// uid/gid change or setuid bits fire.
    pub pdeathsig: AtomicU32,

    /// Linux `PF_MEMALLOC_NOIO | PF_LOCAL_THROTTLE` (`prctl(PR_SET_IO_FLUSHER)`).
    /// Read by the page allocator's reclaim decision so a userspace block
    /// server never re-enters IO through its own allocations.
    pub io_flusher: crate::prctl::io_flusher::IoFlusher,

    /// Linux `task_struct::syscall_dispatch`
    /// (`prctl(PR_SET_SYSCALL_USER_DISPATCH)`). Consumed by the syscall
    /// dispatch head, which rolls the call back and raises SIGSYS for every
    /// syscall the registration claims.
    pub syscall_dispatch: crate::prctl::sud::SyscallUserDispatch,

    /// Linux `thread_info::syscall_work`: one per-task word decides whether
    /// uncommon syscall entry/exit work runs. The tracepoint bit is stamped on
    /// every live task when either syscall trace event is registered, so the
    /// disabled path pays this word's existing flag test rather than entering
    /// an AtomicPtr hook wrapper twice per syscall.
    pub(crate) syscall_work: AtomicU32,

    /// `personality(2)` execution domain. 0 = PER_LINUX, the v1 default.
    /// Stored per-task; `personality()` returns the previous value and
    /// updates atomically when arg != 0xFFFFFFFF.
    pub personality: AtomicU32,


    /// Owned network namespace membership. `None` after task exit releases
    /// membership, even while a pidfd keeps this `Task` allocation alive.
    net_namespace: Spinlock<Option<NetworkNamespaceRef>, Namespace>,

    /// Virtualised tgid as seen from this task's pid_ns. `0` means
    /// "use the real tgid" (init-NS shortcut).
    pub vtgid:  AtomicU32,
    /// Virtualised tid (per-thread) as seen from this task's pid_ns.
    /// `0` means "use the real tid".
    pub vtid:   AtomicU32,
    /// PTRACE_SYSCALL armed: self-stop+SIGTRAP at syscall entry+return.
    pub ptrace_syscall_armed: AtomicBool,
    /// Linux `PT_SEIZED`: the tracer attached with PTRACE_SEIZE rather than
    /// PTRACE_ATTACH. PTRACE_INTERRUPT and PTRACE_LISTEN are EIO without it.
    pub ptrace_seized: AtomicBool,
    /// ABI return-value register (`user_regs_struct.ax` / `user_pt_regs.x0`)
    /// as of the current ptrace-stop. The saved entry frame keeps the syscall
    /// number in that slot (`orig_ax`), so Linux's value — `-ENOSYS` at a
    /// syscall-entry stop, the result at a syscall-exit stop — is recorded
    /// here by the stop hook instead of being reconstructed from the frame.
    pub ptrace_stop_rax: AtomicU64,
    /// wait4/waitid WUNTRACED/WCONTINUED flags plus the pending stop code.
    /// `stop_code` is Linux's `exit_code` for a stop, which is 16 bits wide,
    /// not a bare signal number: a ptrace event stop carries
    /// `SIGTRAP | (PTRACE_EVENT_* << 8)` and a syscall stop carries
    /// `SIGTRAP | 0x80`. `syscall::ptrace` composes and decodes it; the wait
    /// status is `syscall::wait::stopped_wstatus(stop_code)`.
    pub stop_pending: AtomicBool, pub cont_pending: AtomicBool, pub stop_code: AtomicU32,
    /// Per-task hardware debug-register shadow: DR0-DR3 addresses, then the
    /// DR6 status and DR7 control. Installed into hardware by the context
    /// switch when armed and read/written by `PTRACE_PEEKUSER`/`POKEUSER` on
    /// the `u_debugreg` window. Arch-neutral storage; the bit contract belongs
    /// to the HAL (`debugreg::x86`).
    ///
    /// LAZY: one pointer, null until a breakpoint is actually armed. `Task` is
    /// built on the boot stack and the deepest aarch64 syscall path runs within
    /// single-digit bytes of the stack ceiling, so an inline register file here
    /// is a stack-budget regression rather than merely wasted memory.
    pub debugregs: crate::debugreg::slab::Lazy<crate::debugreg::Shadow>,
    /// aarch64 per-task hardware breakpoint / watchpoint register file — up to
    /// 16 breakpoint plus 16 watchpoint slots, so LAZY for the same
    /// stack-budget reason as `debugregs` above. Same single-mutator discipline
    /// as `fpu_state` (`13§5`) once allocated: the owning task on its own CPU,
    /// or a tracer while the tracee is ptrace-stopped.
    #[cfg(target_arch = "aarch64")]
    pub hw_break: crate::debugreg::slab::Lazy<crate::debugreg::arm::Shadow>,
    /// Linux `task->jobctl`: the job-control / ptrace-trap latch. Bit layout
    /// and every rule read off it are `crate::jobctl`.
    pub jobctl: AtomicU64,

    /// `rseq(2)` registration pointer — per-THREAD user pointer to a
    /// `struct rseq`. Non-zero means every exit to user republishes the ids
    /// and the IRQ-exit tail performs the critical-section abort
    /// (`crate::rseq`). Reset by execve; inherited across a non-CLONE_VM
    /// fork, cleared for a CLONE_VM child (Linux `rseq_fork`).
    pub rseq_ptr: AtomicU64,
    /// Length of the registered area, validated against Linux
    /// `rseq_length_valid` and matched on re-register/unregister.
    pub rseq_len: AtomicU32,
    /// Abort signature. The four bytes below a critical section's `abort_ip`
    /// must equal it or the abort is fatal — this is what keeps a writable
    /// `rseq_cs` from redirecting execution at an arbitrary gadget.
    pub rseq_sig: AtomicU32,
    /// Cache of the (cpu_id, mm_cid) pair last published into the rseq area,
    /// so an exit to user that did not change CPU costs no user writes.
    /// `crate::rseq::exit::IDS_UNSET` = nothing published yet.
    pub rseq_ids: AtomicU64,
    /// Slice-extension opt-in for a v2 rseq registration. The kernel owns the
    /// matching user `flags` bit and clears this state on registration teardown.
    pub rseq_slice_enabled: AtomicBool,
    /// An outstanding bounded slice grant. The return-to-user path clears the
    /// matching user control word before a regular reschedule can proceed.
    pub rseq_slice_granted: AtomicBool,
    /// Absolute monotonic expiry for the outstanding slice grant, or zero.
    pub rseq_slice_expires_ns: AtomicU64,
    /// Linux `task_struct::rseq.slice.yielded` — read-and-cleared by
    /// `rseq_slice_yield(2)` (slot 471). Set by `rseq_syscall_enter_work` when
    /// a GRANTED time-slice extension is relinquished through that syscall.
    pub rseq_slice_yielded: AtomicBool,

    /// POSIX credentials per `13§5` / docs/14 cred-ABI block.
    /// Real ruid/euid/suid + fsuid mirror; same triple for gid.
    /// Init starts as root (all zero). fork copies, execve preserves.
    /// Single-mutator: the running task on this CPU is the sole writer
    /// (setuid family runs on the calling task only).
    pub creds: Creds,
    #[cfg(feature = "debug-smp")]
    pub dbg_canary_tail: AtomicU64,
}
