// Task descriptor manifest for the scheduler per `13§5`.
//
// Module map:
// - types: signal info, scheduling policy/class, task state.
// - creds: POSIX credentials and capability helpers.
// - audit_identity: per-task login uid/session identity and fork inheritance.
// - dup: refcounted Task allocation (`dup_task_struct` shape) — construct into
//   the Arc, never onto the creator's kernel stack.
// - signals: sigaction storage plus mm/rlimit accessors.
// - arch: opaque arch context/FPU buffers and POSIX timer slot type.
// - methods: constructors/fd-table/stack/context/state/pid; load: blocked-load handoff.
// - util: task-owned PELT utilization and I/O-wait state for schedutil.
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
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicI8, AtomicI32, AtomicPtr, AtomicU16, AtomicU32, AtomicU64, AtomicU8};
#[cfg(feature = "debug-task-fpu-provenance")]
use core::sync::atomic::AtomicUsize;

use sync::{Namespace, Spinlock, TaskList as TaskListClass, TaskWake as TaskWakeClass};
use vfs::FdTable;
use vmm::AddressSpace;
use network_namespace::NetworkNamespaceRef;
use cpu::AtomicCpuMask;

mod arch;
#[path = "task/core.rs"]
mod task_core;
#[path = "task/security.rs"]
mod task_security;
mod audit_identity;
pub mod cap;
mod comm;
pub mod dup;
pub(crate) mod creds;
mod exe_path;
mod parent_arc;
mod proc_strings;
mod rlimits;
mod fd_table;
mod mm_slot;
mod fs_context;
mod io_context;
pub mod io_uring;
mod lifetime; mod load; mod util;
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
pub use task_core::TaskCore;
pub use task_security::TaskSecurity;
pub use comm::set_comm_hook;
pub use creds::{securebits, Creds, GroupList};
pub use fs_context::{FsContext, FsContextSnapshot, UMASK_MASK};
pub use io_context::current_ioprio;
pub use namespaces::TaskNamespaceSnapshot;
pub use restart::RestartBlock;
pub use signals::{SaHandler, SigActions, SignalPending, SA_IMMUTABLE, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK};
pub use sigwake::{interruptible_work_pending, SleepWake, WaitOutcome, WaitState, signal_pending_state};
pub use types::{SchedClass, SchedPolicy, SigInfo, TaskState, RT_QUEUE_CAP};
#[cfg(feature = "debug-watchdog")]
pub use types::WakeDiagPhase;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingWake { Drop, Ready, Defer }

/// The last syscall entry saved for `/proc/<pid>/syscall`. The snapshot is
/// replaced at entry and remains readable after the task blocks or is
/// descheduled, matching Linux's `task_current_syscall` source. # C: O(1)
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyscallSnapshot {
    pub nr: u32,
    pub args: [u64; 6],
    pub sp: u64,
    pub ip: u64,
}

pub use uapi::{MCE_KILL_EARLY, MCE_KILL_PROCESS, SUID_DUMP_DISABLE, SUID_DUMP_ROOT,
    SUID_DUMP_USER, TASK_COMM_LEN, THP_DISABLE_COMPLETELY, THP_DISABLE_EXCEPT_ADVISED,
    THP_DISABLE_OFF};

pub struct Task {
    pub core: TaskCore,

    /// Per-thread nested native NT callback continuations.
    pub nt_callback_stack: Spinlock<crate::nt_callback::Stack, TaskListClass>,

    /// Per-thread native NT APC records, retained until user APC delivery.
    pub nt_apc_queue: crate::nt_apc::Queue,

    /// Per-thread native NT exception state, retained until the Windows user
    /// dispatcher resolves or terminates the exception.
    pub nt_exception: crate::nt_exception::State,

    /// Top of kernel stack (one-past-end). AtomicPtr; read-only on hot.
    pub kernel_stack: AtomicPtr<u8>,

    /// Memcg that owned the kernel-stack allocation at creation. A task move
    /// never transfers this charge; final Task release does.
    pub kernel_stack_memcg: AtomicU64,
    /// Exact charged byte extent, retained with the Box for final release.
    pub kernel_stack_charge_bytes: AtomicU64,

    /// Backing storage for the kernel stack — allocated by the spawn path and
    /// released by the context-switch tail once this task is off-CPU for the
    /// last time (Linux `put_task_stack` in `finish_task_switch`), NOT when the
    /// `Arc<Task>` drops. A zombie waiting to be reaped is a task that has
    /// finished running, so holding its stack until the parent calls `wait4`
    /// pins 16 KiB per unreaped child for no reason — and it is what forces the
    /// exit notification onto the switch tail, since a parent that reaped
    /// earlier would free the stack out from under a task still running on it.
    ///
    /// `None` for tasks that own no stack (idle, boot frame, hosted fixtures)
    /// and for one whose stack has been released. The pointer in `kernel_stack`
    /// aliases `stack[stack.len()]` (one past the last byte = top-of-stack on
    /// x86_64 / aarch64) and is cleared with it.
    pub stack: Spinlock<Option<crate::kstack::GuardedStack>, TaskListClass>,

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
    /// io_uring filters this task imposed on ITSELF, in registration order.
    /// Inherited across fork and kept across `execve` — like seccomp, a
    /// confinement a task accepts must not be shed by replacing its image, or
    /// the confinement is advisory. Every ring the task creates starts from
    /// this set.
    pub io_uring_filters: Spinlock<Option<alloc::vec::Vec<io_uring::IouFilterReg>>,
        TaskListClass>,
    /// io_uring restrictions this task imposed on ITSELF — the ring-less form
    /// of `IORING_REGISTER_RESTRICTIONS`. Every ring the task later creates
    /// starts from this allow-list, so a confined process cannot escape by
    /// opening a fresh ring. `Some` — even `Some` of an EMPTY list — means the
    /// task has registered, which is both what makes a second registration
    /// refuse and what makes an empty registration forbid everything rather
    /// than allow everything.
    pub io_uring_restrict: Spinlock<Option<alloc::vec::Vec<io_uring::IouRestrictReg>>,
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

    /// Child-owned Linux `task_struct::vfork_done` completion. The parent
    /// waits on this object and exec/exit completes it; the state and wait
    /// queue therefore have one owner instead of a global TID lookup.
    pub vfork_completion: Arc<crate::vfork_completion::VforkCompletion>,

    /// Source position of the wait this task is blocked in — the datum
    /// `/proc/<pid>/wchan` reports. See [`crate::park_site`].
    pub park_site: crate::park_site::ParkSite,

    /// Linux `task_struct::last_switch_count` / `last_switch_time`: what the
    /// hung-task scan last observed of `nvcsw + nivcsw`, and when. Written
    /// only by that single scanning kthread, so no ordering beyond Relaxed is
    /// owed. See [`crate::hung_task`].
    pub hung_last_switch_count: AtomicU64,
    pub hung_last_switch_ns: AtomicU64,

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
    pub security: TaskSecurity,

}
