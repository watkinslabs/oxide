// Task descriptor manifest for the scheduler per `13§5`.
//
// Module map:
// - types: signal info, scheduling policy/class, task state.
// - creds: POSIX credentials and capability helpers.
// - signals: sigaction storage plus mm/rlimit accessors.
// - arch: opaque arch context/FPU buffers and POSIX timer slot type.
// - methods: constructors, fd-table, stack, context, state, and pid helpers.
// - namespaces: atomic concrete namespace-set ownership and lifetime operations.
// - net_namespace: owned network-namespace membership slot operations.
// - cap: Linux CAP_* constants.

extern crate alloc;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI8, AtomicI32, AtomicPtr, AtomicU16, AtomicU32, AtomicU64, AtomicU8};

use sync::{Namespace, Spinlock, TaskList as TaskListClass};
use vfs::FdTable;
use vmm::AddressSpace;
use network_namespace::NetworkNamespaceRef;

mod arch;
pub mod cap;
mod creds;
mod methods;
mod net_namespace;
mod namespaces;
mod signals;
mod types;

pub use arch::{ArchCtxBuf, ArchFpuBuf, PosixTimer};
pub use creds::Creds;
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
    pub cpu:      AtomicU16,
    pub vruntime: AtomicU64,
    /// Monotonic ns this task last (re)started running; update_curr charges
    /// `now - exec_start` to runtime+vruntime then re-stamps. 0 = never-run.
    pub exec_start_ns: AtomicU64,
    /// Total CPU time (ns) consumed — /proc/<pid>/stat utime + cgroup cpu (`13§3`).
    pub sum_exec_runtime_ns: AtomicU64,
    pub last_syscall_nr: AtomicU32, // diag: last syscall nr entered (u32::MAX=none); stamped in diag::note_syscall
    pub nsyscalls: AtomicU64,        // diag: monotonic syscall-entry count (sysrq/watchdog dump)
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

    /// Backing storage for the kernel stack — allocated by the
    /// spawn path, freed when the `Arc<Task>` drops. `None` for
    /// tasks that don't own a stack (idle, boot frame, hosted tests
    /// constructing Tasks for runqueue logic only). The pointer
    /// in `kernel_stack` aliases `stack[stack.len()]` (one past
    /// the last byte = top-of-stack on x86_64 / aarch64).
    pub stack: Option<Box<[u8]>>,

    /// Opaque per-arch HAL `Context` (per `14§5.2`/`14§6.2`). Sized
    /// to `ARCH_CTX_SIZE`; aligned for the arch-specific Context's
    /// first field. Access gated by the runqueue invariant.
    pub arch_ctx: UnsafeCell<ArchCtxBuf>,

    /// Per-task user address space per `13§5` / `11§3`. `None` for
    /// kthreads. `Arc`-shared so `CLONE_VM` siblings share the
    /// VMA tree; `execve` replaces in-place under the single-
    /// mutator-per-CPU invariant.
    pub mm: UnsafeCell<Option<Arc<AddressSpace>>>,

    /// Per-task open-file table per `13§5` / `16§3`. `None` for
    /// tasks that don't carry one (kthreads, the boot-anchor
    /// idle). Shared via `Arc` per `clone3` semantics: `CLONE_FILES`
    /// siblings share the same table; default fork copies entries
    /// (v1: shares the Arc, deferring per-entry copy until needed).
    /// Wrapped in `UnsafeCell` for `dup2` / `close` / `execve`
    /// (CLOEXEC) — single-mutator-per-active-CPU invariant.
    pub fd_table: UnsafeCell<Option<Arc<FdTable>>>,

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

    /// Weak-ref to parent Task per `27§5` SIGCHLD delivery. Set
    /// by `sys_fork` when this task is constructed; `None` for
    /// tasks with no parent (boot-anchor idle, kthreads). Read by
    /// `park_zombie` to upgrade + post SIGCHLD pending bit on the
    /// parent. Wrapped in `UnsafeCell` because spawn writes it
    /// once before the runqueue sees the task; same single-
    /// mutator invariant as `mm`.
    pub parent_arc: UnsafeCell<Option<Weak<Task>>>,

    /// User-side argv string per `19§4` for `/proc/self/cmdline`.
    /// Set at `sys_execve` time to a NUL-separated copy of argv;
    /// `None` for tasks without an execve (boot's init-anchor
    /// uses `task.name` as a fallback). Wrapped in `UnsafeCell`
    /// for the same single-mutator invariant as `mm`.
    pub cmdline: UnsafeCell<Option<alloc::string::String>>,

    /// F200: controlling terminal (POSIX §11.1.3). None = no ctty.
    /// Cleared at setsid(2); set at TIOCSCTTY; inherited at fork(2).
    pub ctty: UnsafeCell<Option<vfs::InodeRef>>,

    /// Absolute path passed to the most recent `sys_execve(path,…)`,
    /// per Linux `/proc/<pid>/exe`. Distinct from `cmdline` (which
    /// stores argv[0..]; argv[0] is conventionally the basename
    /// the program was invoked as, not its filesystem path).
    /// Programs readlink `/proc/self/exe` to discover their
    /// own binary path; without the real exec path here, multi-call
    /// binaries misbehave. Single-mutator per `13§5`.
    pub exe_path: UnsafeCell<Option<alloc::string::String>>,

    /// Current working directory per POSIX getcwd(3) / chdir(2).
    /// Always an absolute path. `sys_chdir` / `sys_fchdir` write,
    /// `sys_getcwd` reads. Default "/" for boot tasks; fork inherits
    /// from parent. Same single-mutator invariant per `13§5`.
    pub cwd: UnsafeCell<alloc::string::String>,
    /// Current working directory as a VFS path object. This is the Linux
    /// ownership shape (`fs_struct::pwd`): path operations should use this
    /// instead of re-resolving `cwd` as a string. `cwd` remains the rendered
    /// user-visible pathname for getcwd/proc while callers migrate.
    pub cwd_vfs: UnsafeCell<Option<vfs::VfsPath>>,

    /// User-side envp string per `19§4` for `/proc/<pid>/environ`.
    /// NUL-separated copy of `envp[0..envc]`, written at execve time.
    pub environ: UnsafeCell<Option<alloc::string::String>>,

    /// Per-task rlimits per POSIX getrlimit(2) / prlimit64(2).
    /// 16 slots indexed by `RLIMIT_*`; each is `(cur, max)`. Linux
    /// init defaults installed at Task::new (see `crate::rlimit::
    /// DEFAULT_RLIMITS`): RLIMIT_STACK = (8 MiB, RLIM_INFINITY),
    /// the rest unlimited. Fork inherits per POSIX. Same
    /// single-mutator invariant as `mm`.
    pub rlimits: UnsafeCell<[(u64, u64); 16]>,

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

    /// Legacy `chroot(2)` root text. Default "/" — retained only for old
    /// diagnostics; live absolute path walks use `root_vfs` below. Single-mutator
    /// per `13§5`. Inherited by fork/clone; cleared only via explicit chroot.
    pub root: UnsafeCell<alloc::string::String>,
    /// Per-task resolution root as a VFS path object (`fs_struct::root`).
    /// Absolute path walks should start here after chroot instead of treating
    /// root as a string prefix.
    pub root_vfs: UnsafeCell<Option<vfs::VfsPath>>,

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
