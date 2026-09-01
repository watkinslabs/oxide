//! Core identity, wake, lifecycle, accounting, and scheduling state owned by a task.

use super::*;

pub struct TaskCore {
    #[cfg(feature = "debug-smp")]
    pub dbg_canary_head: AtomicU64,
    pub tid:  u32,
    /// Thread-group id per Linux clone(CLONE_THREAD) semantics —
    /// the leader's `tid` shared by every thread in the same
    /// process. `getpid()` returns this; `gettid()` returns `tid`.
    /// For non-CLONE_THREAD spawns (fork) `tgid == tid`.
    pub tgid: AtomicU32,
    /// PEB address published by an NT PE exec, used by native process queries.
    pub nt_peb: AtomicU64,
    /// TEB address published by an NT PE exec for this thread.
    pub nt_teb: AtomicU64,
    /// Thread-local Windows preferred UI-language multi-string and input mode.
    pub nt_thread_ui_languages: Spinlock<(u32, alloc::vec::Vec<u16>), TaskListClass>,
    /// Native NT job identity assigned to this process, or zero when free.
    pub nt_job_id: AtomicU64,
    /// Canonical PID identity, retained by pidfds after `release_task`.
    pub pid: Arc<crate::pid::PidIdentity>,
    /// Stable process thread-group owner.
    pub thread_group: Arc<crate::thread_group::ThreadGroup>,
    /// Linux `task_struct::comm` — mutable, NUL-padded, per-THREAD. Set at
    /// spawn/execve/fork-clone/`prctl(PR_SET_NAME)`; use `task/comm.rs`
    /// accessors, not this field directly (sole comm storage, `07§5`).
    pub name: Spinlock<[u8; TASK_COMM_LEN], TaskListClass>,

    pub state:    AtomicU8,
    /// Serializes the Sleeping→Runnable claim with affinity changes through
    /// the subsequent CPU-selection/enqueue decision. This is the task wake
    /// serialization boundary; it is acquired before a runqueue lock.
    pub task_wake_lock: Spinlock<(), TaskWakeClass>,
    /// Diagnostic-only phase/timestamp for a claimed wake.  Absent outside
    /// watchdog builds so it cannot alter the scheduler's steady-state layout.
    #[cfg(feature = "debug-watchdog")]
    pub wake_diag_phase: AtomicU8,
    #[cfg(feature = "debug-watchdog")]
    pub wake_diag_ns: AtomicU64,
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
    /// Frozen acknowledgement. Set only by the target at a safe checkpoint;
    /// once set, the enqueue chokepoint holds it off every runqueue.
    pub frozen:   AtomicBool,
    /// Pending/held freezer requests: cgroup v2, system sleep (`32a§10`), or
    /// both. A task may temporarily have a request without `frozen` while it
    /// finishes kernel work and reaches its own checkpoint.
    pub freeze_reasons: AtomicU8,
    /// Linux `PF_NOFREEZE`: never frozen by system sleep. Kernel threads start
    /// with it and explicitly opt in at a lock-free checkpoint; userspace does
    /// not. The cgroup v2 freezer is independent of this flag.
    pub nofreeze: AtomicBool,
    /// Linux `PF_SUSPEND_TASK`: this task asked for the suspend. Freezing it
    /// would deadlock the machine against itself.
    pub suspend_task: AtomicBool,
    /// NT per-thread suspend depth, owned by the task rather than an NT-side
    /// shadow table so all thread-control paths observe one counter.
    pub nt_suspend_count: AtomicU32,
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
    /// Linux `se.avg.util_avg`: exponentially decayed runnable utilization.
    /// It is updated only at scheduler ownership boundaries and consumed by
    /// the cpufreq update-util hook; it is not reconstructed from tick totals.
    pub util_avg: AtomicU32,
    pub util_last_update_ns: AtomicU64,
    /// Set while this task is parked waiting for a device completion. The
    /// wake path consumes it to raise schedutil's iowait boost exactly once.
    pub in_iowait: AtomicBool,
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
    pub syscall_snapshot: Spinlock<SyscallSnapshot, TaskListClass>,
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
    pub cpus_allowed: AtomicCpuMask,
    /// Linux `task_struct::user_cpus_ptr` — the mask `sched_setaffinity(2)`
    /// last requested, kept apart from the effective mask so a later cgroup
    /// `cpuset.cpus` change re-applies the user's request instead of erasing
    /// it. `0` = never set.
    pub user_cpus_allowed: AtomicCpuMask,
    /// Linux `cpuset_cpus_allowed(p)` — the mask the task's cpuset permits.
    /// Default all-ones (no cpuset restriction).
    pub cpuset_cpus_allowed: AtomicCpuMask,
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

}
