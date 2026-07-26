// Task descriptor manifest for the scheduler per `13§5`.
//
// Module map:
// - types: signal info, scheduling policy/class, task state.
// - creds: POSIX credentials and capability helpers.
// - signals: sigaction storage plus mm/rlimit accessors.
// - arch: opaque arch context/FPU buffers and POSIX timer slot type.
// - methods: constructors, fd-table, stack, context, state, and pid helpers.
// - exe_path: pin-locked /proc/<pid>/exe path accessors (clone/with/set).
// - namespaces: atomic concrete namespace-set ownership and lifetime operations.
// - net_namespace: owned network-namespace membership slot operations.
// - fs_context: Linux-shaped shared root/pwd ownership and snapshots.
// - cap: Linux CAP_* constants.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI8, AtomicI32, AtomicPtr, AtomicU16, AtomicU32, AtomicU64, AtomicU8, AtomicUsize};

use sync::{Namespace, Spinlock, TaskList as TaskListClass};
use vfs::FdTable;
use vmm::AddressSpace;
use network_namespace::NetworkNamespaceRef;

mod arch;
pub mod cap;
pub(crate) mod creds;
mod exe_path;
mod parent_arc;
mod proc_strings;
mod rlimits;
mod fd_table;
mod fs_context;
mod lifetime;
mod methods;
mod net_namespace;
mod namespaces;
mod signals;
mod types;

pub use arch::{ArchCtxBuf, ArchFpuBuf, PosixTimer};
pub use creds::Creds;
pub use fs_context::{FsContext, FsContextSnapshot};
pub use namespaces::TaskNamespaceSnapshot;
pub use signals::{SaHandler, SigActions, SignalPending, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK};
pub use types::{SchedClass, SchedPolicy, SigInfo, TaskState, RT_QUEUE_CAP};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingWake { Drop, Ready, Defer }

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
    pub name: &'static str,

    pub state:    AtomicU8,
    pub on_rq:    AtomicBool,
    /// SMP `on_cpu` (Linux): true while executing on a CPU; set on switch-to,
    /// cleared in finish_task_switch after register save; remote ttwu spins on it.
    pub on_cpu:   AtomicBool,
    /// cgroup v2 freezer: held off every runqueue (enqueue no-op) until thawed.
    pub frozen:   AtomicBool,
    /// Linux `sched_yield`: consumed by `schedule()` before re-enqueueing current.
    pub yield_pending: AtomicBool,
    /// True once `wait4`/`waitid` has collected this task's exit status (Linux
    /// `release_task`). The Task may still be pinned alive by an open pidfd, but
    /// a reaped process MUST vanish from `/proc`: procfs enumeration
    /// (`live_vpids`/`live_tids`/`live_counts`) skips reaped tasks, so ps/htop
    /// never show a reaped-but-pidfd-pinned child as a lingering zombie.
    pub reaped:   AtomicBool,
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
    pub last_syscall_nr: AtomicU32, // diag: last syscall nr entered (u32::MAX=none); stamped in diag::note_syscall
    pub nsyscalls: AtomicU64,        // diag: monotonic syscall-entry count (sysrq/watchdog dump)
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
    /// CPU-affinity mask (bit N = may run on CPU N); `sched_setaffinity(2)` +
    /// cgroup `cpuset.cpus`. Balancer/ttwu won't place outside it. Default
    /// all-ones; inherited on fork.
    pub cpus_allowed: AtomicU64,
    /// Encoded `SchedClass` (lock-free; read via `sched_class()`, mutated via
    /// `set_sched_class()` so sched_setattr/setparam can change policy at runtime).
    pub class_enc: AtomicU64,

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

    /// Process group id per `28§4` / POSIX setpgid(2). Initialised
    /// to `tid` (each task is its own pgrp leader by default).
    /// Updated by `sys_setpgid` / `sys_setsid`. Job control + `kill(-pgid)`
    /// signal delivery rely on this; getty / shells rewrite it.
    pub pgid: AtomicU32,

    /// Session id (POSIX setsid). Init = `tid`. # C: O(1)
    pub sid:  AtomicU32,

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

    /// Pending signal bitmap per `27§3` (Linux kernel_sigset_t = 64
    /// bits). Bit i set ⇔ signal i+1 pending. Updated atomically by
    /// `kill`/`tgkill` from any CPU; checked at syscall return per
    /// `27§5` ("signals delivered on transition to user mode").
    /// # C: O(1)
    pub sigpending: SignalPending,

    /// Per-RT-signal (33..=64) siginfo_t queue. RT signals preserve
    /// multiplicity per POSIX RT semantics: every `sigqueue(SIGRTn,
    /// val)` enqueues a distinct (signo,val,pid,uid,code) record.
    /// 32 slots indexed by `sig - 33`. Standard signals 1..=31 use
    /// only the bitmap (Linux semantic: standard signals collapse).
    /// Per-signal queue cap is `RT_QUEUE_CAP`; overflow drops the
    /// new arrival (matches Linux post-RLIMIT_SIGPENDING behavior).
    /// # C: O(1) push / O(1) pop
    pub rt_sigqueue: Spinlock<[VecDeque<SigInfo>; 32], TaskListClass>,

    /// B117: per-parent SIGCHLD child-exit event queue (`27§5`,
    /// siginfo(7)). SIGCHLD(17) collapses in `sigpending`, but an
    /// SA_SIGINFO handler still needs the child's si_pid/si_status/
    /// si_code. Each child pushes one `SigInfo`: `pid`=child VPID
    /// (vtgid, NOT internal tid), `code`=CLD_*, `value`=exit status.
    /// Delivery pops the oldest record; empty ⇒ zeroed siginfo.
    /// # C: O(1) push / O(1) pop
    pub child_sigq: Spinlock<VecDeque<SigInfo>, TaskListClass>,

    /// Per-task signal mask per `27§3`. Bit i set ⇔ signal i+1
    /// blocked. `rt_sigprocmask` writes; signal-delivery checks.
    /// # C: O(1)
    pub sigmask: AtomicU64,

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

    /// F200: controlling terminal (POSIX §11.1.3). None = no ctty.
    /// Cleared at setsid(2); set at TIOCSCTTY; inherited at fork(2).
    pub ctty: UnsafeCell<Option<vfs::InodeRef>>,

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

    /// Linux `fs_struct` analogue: shared by `CLONE_FS` tasks and replaced by
    /// `unshare(CLONE_FS)`.  Private so readers/writers must use owned
    /// snapshots and cannot race pivot-root's remote update.
    fs_context: Spinlock<Arc<FsContext>, TaskListClass>,

    /// User-side envp string per `19§4` for `/proc/<pid>/environ`.
    /// NUL-separated copy of `envp[0..envc]`, written at execve time.
    /// Spinlock-protected — same foreign-pid-read rationale as `cmdline`.
    pub environ: Spinlock<Option<alloc::string::String>, TaskListClass>,

    /// Per-task rlimits per POSIX getrlimit(2) / prlimit64(2). 16 slots
    /// indexed by `RLIMIT_*`; each is `(cur, max)`. Linux init defaults
    /// installed at Task::new (see `crate::rlimit::DEFAULT_RLIMITS`):
    /// RLIMIT_STACK = (8 MiB, RLIM_INFINITY), the rest unlimited. Fork
    /// inherits per POSIX. Spinlock-protected: `prlimit64(2)`
    /// (`syscalls/src/302_prlimit64.rs`) and `sched_setattr(2)`'s
    /// RTPRIO/NICE checks (`syscalls/src/314_sched_setattr.rs`) are real
    /// Linux syscalls that read/write an ARBITRARY target task's rlimits
    /// from the caller's own CPU — the same cross-task-write shape as
    /// `parent_arc` (B1329), not a self-only field.
    pub rlimits: Spinlock<[(u64, u64); 16], TaskListClass>,

    /// Per-task nice value per POSIX nice(2)/setpriority(2). Range
    /// nice [-20, 19]; 0 default; inherited on fork. Scheduler
    /// ignores (CFS weight fixed); stored for getpriority /
    /// /proc/<pid>/stat field 19.
    pub nice: AtomicI8,

    /// Per-task I/O priority per ioprio_set/get(2). Packed: class =
    /// `ioprio >> 13` (0=NONE, 1=RT, 2=BE, 3=IDLE), level = low 13 bits.
    /// 0 = IOPRIO_CLASS_NONE (kernel derives from nice). Inherited on
    /// fork; honored by a priority-aware I/O scheduler when present.
    pub ioprio: AtomicU16,

    /// Monotonic ns at spawn; getrusage/times/proc-stat utime
    /// derived as `monotonic_ns() - spawn_ns`. 0 in hosted tests.
    pub spawn_ns: AtomicU64,
    /// Host CLOCK_BOOTTIME ns at task creation; proc stat field 22 applies
    /// the reader's TIME namespace offset before conversion to clock ticks.
    pub start_boottime_ns: u64,
    /// F169 WaitList::park_with_deadline; 0 = indefinite.
    pub wakeup_deadline_ns: AtomicU64,
    /// Cumulative ns of exited children's CPU; read by
    /// getrusage(RUSAGE_CHILDREN).
    pub cumulative_child_ns: AtomicU64,

    /// Per-task user-mode CPU time (ns), tick-sampled at the timer IRQ
    /// (Linux CONFIG_TICK_CPU_ACCOUNTING); read by getrusage/times/proc-stat.
    pub utime_ns: AtomicU64,
    /// Per-task kernel-mode CPU time (ns), tick-sampled at the timer IRQ
    /// (Linux CONFIG_TICK_CPU_ACCOUNTING); read by getrusage/times/proc-stat.
    pub stime_ns: AtomicU64,
    /// Cumulative user-mode CPU time (ns) of reaped children; read by
    /// getrusage(RUSAGE_CHILDREN).ru_utime + times().tms_cutime.
    pub cumulative_child_utime_ns: AtomicU64,
    /// Cumulative kernel-mode CPU time (ns) of reaped children; read by
    /// getrusage(RUSAGE_CHILDREN).ru_stime + times().tms_cstime.
    pub cumulative_child_stime_ns: AtomicU64,

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

    /// Per-task umask per POSIX umask(2). Default 0o022. Fork
    /// inherits. AND-NOT with mode in sys_open/openat(O_CREAT).
    pub umask: AtomicU32,

    /// CLONE_CHILD_CLEARTID address per set_tid_address(2). Linux
    /// stores the user pointer; on thread exit, writes 0 to the
    /// addr + FUTEX_WAKE_PRIVATE. v1 stores for visibility; no
    /// per-thread cleanup in the single-thread model.
    pub clear_child_tid: AtomicU64,

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

    /// landlock ruleset-id chain. landlock_restrict_self appends;
    /// path-based syscalls consult; entries can't be removed.
    pub landlock_chain: Spinlock<alloc::vec::Vec<u64>, TaskListClass>,
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
    /// F206 aarch64 per-task SVC-frame ptr; deliver_arm reads here.
    #[cfg(target_arch = "aarch64")]
    pub svc_frame: core::sync::atomic::AtomicU64,
    /// Per-task seccomp cBPF chain per `13§5`. Drop on task exit.
    pub seccomp_filters: UnsafeCell<alloc::vec::Vec<alloc::vec::Vec<u64>>>,

    /// Per-thread robust-mutex list head + len per
    /// `set_robust_list(2)` (slot 273) and Linux `struct robust_list_head`.
    /// glibc/musl pass a thread-local pointer at startup; on thread
    /// exit the kernel walks the list and wakes contending futexes
    /// (substrate for that walk rides a follow-up). Storing real
    /// values means `get_robust_list` returns what userspace set.
    pub robust_list_head: AtomicU64,
    pub robust_list_len:  AtomicU64,

    /// POSIX timers per `timer_create(2)`. Fixed-size array of slots;
    /// each slot is either free (`signo == 0`), allocated-disarmed
    /// (`deadline_ns == 0`), or armed (`deadline_ns > 0`). Single-
    /// mutator on the running task per `13§5`.
    pub posix_timers: UnsafeCell<[PosixTimer; PosixTimer::SLOTS]>,

    /// Linux `PR_SET_NO_NEW_PRIVS` flag. Once set, the task and its
    /// descendants can no longer gain privileges via setuid binaries
    /// or capability-conferring file caps. Sticky: clearing is not
    /// allowed by Linux; we mirror that.
    pub no_new_privs: AtomicBool,

    /// Per-task timer-slack value in nanoseconds, controlled by
    /// `prctl(PR_SET_TIMERSLACK)`. Linux defaults it to 50 microseconds;
    /// zero passed to the setter restores that default.
    pub timer_slack_ns: AtomicU64,

    /// `PR_SET_PDEATHSIG` — signal delivered to this task when its
    /// parent exits. `0` means "no signal". Cleared by execve when
    /// uid/gid change or setuid bits fire.
    pub pdeathsig: AtomicU32,

    /// `PR_SET_CHILD_SUBREAPER` flag. When 1, orphaned descendants
    /// re-parent to this task instead of init.
    pub child_subreaper: AtomicBool,

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
    /// wait4 WUNTRACED/WCONTINUED flags + stop signal.
    pub stop_pending: AtomicBool, pub cont_pending: AtomicBool, pub stop_signal: AtomicU8,

    /// `rseq(2)` registration pointer. Per-task user-space pointer to a
    /// `struct rseq` (32 bytes). When non-zero, the syscall-return tail
    /// writes the current cpu_id (always 0 on v1 UP) into offsets 0
    /// (cpu_id_start) and 4 (cpu_id) so glibc's fast-path sees correct
    /// data instead of stale zeros from initialisation.
    pub rseq_ptr: AtomicU64,
    /// Length of the user `struct rseq` (typically 32). Stored to
    /// validate the writeback range fits in user memory.
    pub rseq_len: AtomicU32,
    /// 4-byte signature passed at registration; used by glibc/musl as
    /// a cookie. Stored but not enforced by the kernel.
    pub rseq_sig: AtomicU32,

    /// POSIX credentials per `13§5` / docs/14 cred-ABI block.
    /// Real ruid/euid/suid + fsuid mirror; same triple for gid.
    /// Init starts as root (all zero). fork copies, execve preserves.
    /// Single-mutator: the running task on this CPU is the sole writer
    /// (setuid family runs on the calling task only).
    pub creds: Creds,
    #[cfg(feature = "debug-smp")]
    pub dbg_canary_tail: AtomicU64,
}
