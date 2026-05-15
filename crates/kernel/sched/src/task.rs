// Task / SchedClass / TaskState definitions for the runqueue. Mirrors
// the spec's `13§5` shape. `mm` is now real (P2-13a integrates with
// `vmm::AddressSpace` for per-task address spaces). The other Arc'd
// payloads (`fd_table`, `sig`, `creds`, `ns`, `cgroup`) land with
// their consumer subsystems.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI8, AtomicI32, AtomicPtr, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::FdTable;
use vmm::AddressSpace;

use crate::{ARCH_CTX_SIZE, ARCH_FPU_SIZE};

/// Subset of `siginfo_t` per `15§5` carried in the per-task RT
/// signal queue. Standard signals (1..=31) don't queue — they
/// collapse to the pending bitmap and any siginfo at delivery time
/// is synthesised. RT signals (33..=64) queue distinct records
/// per `sigqueue(2)` / `pthread_sigqueue(3)` semantics.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SigInfo {
    pub signo: u32, // signal number 1..=64 (RT: 33..=64)
    pub code:  i32, // si_code (SI_USER=0, SI_QUEUE=-1, …)
    pub pid:   u32, // si_pid
    pub uid:   u32, // si_uid
    pub value: u64, // sigval_t (sigqueue(2) value.sival_int|sival_ptr)
}

/// Per-signal RT queue depth cap. Drops new arrivals past this
/// (Linux drops past `RLIMIT_SIGPENDING`); 64 is generous for v1
/// where we don't yet enforce per-uid pending limits.
pub const RT_QUEUE_CAP: usize = 64;

/// POSIX-style scheduling policy per `13§3`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SchedPolicy {
    /// `SCHED_OTHER` / `SCHED_BATCH` (Normal / CFS class).
    Normal,
    /// `SCHED_FIFO` (RT class) — runs until block.
    Fifo,
    /// `SCHED_RR` (RT class) — round-robin within priority.
    Rr,
    /// Per-CPU idle task; never user-set.
    Idle,
}

/// Class membership; mirrors the per-class data the runqueue needs to
/// pick. `13§3`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SchedClass {
    /// RT priority `1..=99` (higher = higher).
    Rt { prio: u8, policy: SchedPolicy },
    /// Normal-class weight from the Linux nice→weight table; vruntime
    /// is held in `Task::vruntime` so the CFS tree can re-key it on
    /// each insert.
    Normal { weight: u32 },
    /// Per-CPU idle.
    Idle,
}

/// Lifecycle state per `13§5`. Stored as `AtomicU8` for lock-free
/// transitions in `wake_up`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TaskState {
    Runnable = 0,
    Sleeping = 1,
    Stopped  = 2,
    Zombie   = 3,
}

impl TaskState {
    /// # C: O(1)
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Runnable),
            1 => Some(Self::Sleeping),
            2 => Some(Self::Stopped),
            3 => Some(Self::Zombie),
            _ => None,
        }
    }

    /// Linux /proc/<pid>/stat state character per `19§4`.
    /// # C: O(1)
    pub const fn linux_char(self) -> u8 {
        match self {
            Self::Runnable => b'R',
            Self::Sleeping => b'S',
            Self::Stopped  => b'T',
            Self::Zombie   => b'Z',
        }
    }

    /// Long-form Linux state name for /proc/<pid>/status (e.g. "R (running)").
    /// # C: O(1)
    pub const fn linux_status_label(self) -> &'static str {
        match self {
            Self::Runnable => "R (running)",
            Self::Sleeping => "S (sleeping)",
            Self::Stopped  => "T (stopped)",
            Self::Zombie   => "Z (zombie)",
        }
    }
}

/// `13§5` task descriptor — runqueue-relevant fields only.
///
/// Allocation: heap-managed via `Arc<Task>` for v1; replaced by
/// slab-backed allocation per `12§3.2` once the integration lands. The
/// runqueue stores `Arc<Task>` clones and re-keys CFS by the current
/// `vruntime` snapshot on each insert.
///
/// `arch_ctx` is an opaque byte buffer sized to fit any per-arch HAL
/// `Context` record (per `14§4`); access goes through
/// `arch_ctx_ptr::<C>()` which compile-time-asserts the size fits.
/// Mutation discipline is the caller's: the kernel scheduler is the
/// only writer, only when this task is the active one on its CPU
/// (Context::switch saves prev's, loads next's). `unsafe impl Sync`
/// is sound under that single-mutator-per-active-CPU invariant.
pub struct Task {
    pub tid:  u32,
    /// Thread-group id per Linux clone(CLONE_THREAD) semantics —
    /// the leader's `tid` shared by every thread in the same
    /// process. `getpid()` returns this; `gettid()` returns `tid`.
    /// For non-CLONE_THREAD spawns (fork) `tgid == tid`.
    pub tgid: AtomicU32,
    pub name: &'static str,

    pub state:    AtomicU8,
    pub on_rq:    AtomicBool,
    pub cpu:      AtomicU16,
    pub vruntime: AtomicU64,
    pub class:    SchedClass,

    pub exit_status: AtomicI32,

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

    /// Session id per POSIX setsid(2). Initialised to `tid`.
    /// `sys_setsid` sets both `pgid` and `sid` to `tid`, making the
    /// caller a session leader.
    pub sid:  AtomicU32,

    /// Top of this task's kernel stack (one past the last byte).
    /// Set when the task is constructed alongside its arch ctx.
    /// `null` until set; AtomicPtr so reads are race-free across
    /// concurrent CPU views (read-only on hot paths).
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
    pub sigpending: AtomicU64,

    /// Per-RT-signal (33..=64) siginfo_t queue. RT signals preserve
    /// multiplicity per POSIX RT semantics: every `sigqueue(SIGRTn,
    /// val)` enqueues a distinct (signo,val,pid,uid,code) record.
    /// 32 slots indexed by `sig - 33`. Standard signals 1..=31 use
    /// only the bitmap (Linux semantic: standard signals collapse).
    /// Per-signal queue cap is `RT_QUEUE_CAP`; overflow drops the
    /// new arrival (matches Linux post-RLIMIT_SIGPENDING behavior).
    /// # C: O(1) push / O(1) pop
    pub rt_sigqueue: Spinlock<[VecDeque<SigInfo>; 32], TaskListClass>,

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

    /// Per-task `struct sigaction` array per `27§4`. Slot i holds
    /// the handler/flags/mask/restorer for signal i+1 (1..=64).
    /// `rt_sigaction` writes; signal-delivery reads to choose the
    /// dispatch path (SIG_DFL = terminate; SIG_IGN = drop;
    /// non-NULL = build frame + jump). Wrapped in `UnsafeCell` for
    /// the same single-mutator-per-active-CPU invariant as `mm`.
    pub sigactions: UnsafeCell<[SaHandler; 64]>,

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

    /// Absolute path passed to the most recent `sys_execve(path,…)`,
    /// per Linux `/proc/<pid>/exe`. Distinct from `cmdline` (which
    /// stores argv[0..]; argv[0] is conventionally the basename
    /// the program was invoked as, not its filesystem path).
    /// Busybox + glibc readlink `/proc/self/exe` to discover their
    /// own binary path; without the real exec path here, busybox
    /// falls into help-dump mode. Single-mutator per `13§5`.
    pub exe_path: UnsafeCell<Option<alloc::string::String>>,

    /// Current working directory per POSIX getcwd(3) / chdir(2).
    /// Always an absolute path. `sys_chdir` / `sys_fchdir` write,
    /// `sys_getcwd` reads. Default "/" for boot tasks; fork inherits
    /// from parent. Same single-mutator invariant per `13§5`.
    pub cwd: UnsafeCell<alloc::string::String>,

    /// User-side envp string per `19§4` for `/proc/<pid>/environ`.
    /// NUL-separated copy of `envp[0..envc]`, written at execve time.
    pub environ: UnsafeCell<Option<alloc::string::String>>,

    /// Per-task rlimits per POSIX getrlimit(2) / prlimit64(2).
    /// 16 slots indexed by `RLIMIT_*`; each is `(cur, max)`. Default
    /// `(RLIM_INFINITY, RLIM_INFINITY)` for every resource. Fork
    /// inherits per POSIX. Same single-mutator invariant as `mm`.
    pub rlimits: UnsafeCell<[(u64, u64); 16]>,

    /// Per-task nice value per POSIX nice(2)/setpriority(2). Range
    /// nice [-20, 19]; 0 default; inherited on fork. Scheduler
    /// ignores (CFS weight fixed); stored for getpriority /
    /// /proc/<pid>/stat field 19.
    pub nice: AtomicI8,

    /// Monotonic ns at spawn; getrusage/times/proc-stat utime
    /// derived as `monotonic_ns() - spawn_ns`. 0 in hosted tests.
    pub spawn_ns: AtomicU64,
    /// Cumulative ns of exited children's CPU; read by
    /// getrusage(RUSAGE_CHILDREN).
    pub cumulative_child_ns: AtomicU64,

    /// alarm(2)/setitimer ITIMER_REAL deadline in monotonic ns.
    /// `0` = no alarm pending. Dispatch tail compares against
    /// monotonic_ns() and posts SIGALRM (signal 14) when reached.
    pub alarm_ns: AtomicU64,

    /// ITIMER_REAL period in ns. `0` = one-shot. When the deadline
    /// fires, dispatch tail re-arms `alarm_ns = now + interval` if
    /// non-zero. setitimer(0) sets; getitimer(0) reads.
    pub alarm_interval_ns: AtomicU64,

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

    /// Per-task namespace membership bitmap. Bit i set ⇔ this task
    /// has its own slot for namespace i (rather than inheriting the
    /// init-namespace). Bit assignments mirror Linux CLONE_NEW*:
    ///   bit  0 = NEWNS    (mount)        | CLONE_NEWNS    = 0x00020000
    ///   bit  1 = NEWUTS   (uts)          | CLONE_NEWUTS   = 0x04000000
    ///   bit  2 = NEWIPC   (ipc)          | CLONE_NEWIPC   = 0x08000000
    ///   bit  3 = NEWUSER  (user)         | CLONE_NEWUSER  = 0x10000000
    ///   bit  4 = NEWPID   (pid)          | CLONE_NEWPID   = 0x20000000
    ///   bit  5 = NEWNET   (net)          | CLONE_NEWNET   = 0x40000000
    ///   bit  6 = NEWCGROUP                                = 0x02000000
    /// `unshare(2)` sets bits; `setns(2)` clears the affected bit
    /// (rejoining a target namespace identified by an fd; v1 honors
    /// the syscall but doesn't yet have ns-fd machinery).
    /// # C: O(1)
    pub ns_membership: AtomicU64,

    /// Per-NS UTS hostname when bit 1 of `ns_membership` is set.
    /// Empty string means "inherit from global". Single-mutator per
    /// `13§5`. # C: O(1) read
    pub uts_hostname: UnsafeCell<alloc::string::String>,

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

    /// PTRACE_SINGLESTEP arm bit. Resume path sets RFLAGS.TF (x86)
    /// or MDSCR_EL1.SS+SPSR.SS (arm); trap handler clears after one
    /// instruction retires.
    pub singlestep: AtomicU32,

    /// Per-task seccomp filter chain (cBPF programs). Each entry is
    /// a `Vec<u64>` representing 8-byte sock_filter words; the
    /// kernel/seccomp interpreter reinterprets at run time. Single-
    /// mutator per `13§5`; running task on this CPU is the sole
    /// writer. Drop on task exit. # C: O(F × I) per syscall
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

    /// `PR_SET_KEEPCAPS` flag. When 1, transitioning ruid 0→nonzero
    /// preserves the current cap_permitted instead of clearing it.
    /// Reset to 0 on each execve per Linux semantics.
    pub keep_caps: AtomicBool,

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

    /// `chroot(2)` root path. Default "/" — every absolute path
    /// resolves directly. After chroot, devfs::lookup prepends this
    /// path so the task sees a subtree as "/". Single-mutator per
    /// `13§5`. Inherited by fork/clone (children share parent's
    /// chroot view); cleared on execve only via explicit chroot.
    pub root: UnsafeCell<alloc::string::String>,

    /// IPC namespace id (CLONE_NEWIPC). Default 0 (init NS).
    /// SysV shm/sem/msg + POSIX MQ tables are virtualised by this id
    /// so containers see disjoint key spaces.
    pub ipc_ns: AtomicU64,

    /// Net namespace id (CLONE_NEWNET). Default 0 (init NS).
    /// IfaceRegistry filters by this id so unshared tasks see only
    /// their own NS's network interfaces.
    pub net_ns: AtomicU64,

    /// PID namespace id (CLONE_NEWPID). Default 0 (init NS).
    /// Tasks in non-zero pid_ns get virtualized pids via `vtgid`/`vtid`.
    pub pid_ns: AtomicU64,
    /// Virtualised tgid as seen from this task's pid_ns. `0` means
    /// "use the real tgid" (init-NS shortcut).
    pub vtgid:  AtomicU32,
    /// Virtualised tid (per-thread) as seen from this task's pid_ns.
    /// `0` means "use the real tid".
    pub vtid:   AtomicU32,
    /// True if `unshare(CLONE_NEWPID)` ran on this task and the next
    /// fork from it should land the child in a fresh pid_ns. Cleared
    /// by the fork dispatcher.
    pub unshare_pid_pending: AtomicBool,

    /// User namespace id (CLONE_NEWUSER). Default 0 (init NS).
    /// Per-NS cap scoping per `27§R01` lives in F118.
    pub user_ns: AtomicU64,
    /// Parent user_ns id at the moment this task last unshared
    /// CLONE_NEWUSER. Together with `dev_proc_ns::user_ns_parent`
    /// global registry, this lets `has_cap_for(target, cap)` walk
    /// the ancestor chain.
    pub parent_user_ns: AtomicU64,
    /// Cgroup namespace id (CLONE_NEWCGROUP). Default 0 (init NS).
    /// /proc/self/cgroup rebasing is a follow-up (currently a flat
    /// single-cgroup hierarchy — every NS sees "0::/" path).
    pub cgroup_ns: AtomicU64,

    /// Mount namespace id (CLONE_NEWNS). Default 0 (init NS).
    /// V1 substrate only: real mount-table virtualisation is a follow-up
    /// phase 29 (needs ext4 + block). Until then unshare(CLONE_NEWNS)
    /// just allocates an id; mount itself remains EPERM.
    pub mount_ns: AtomicU64,

    /// PTRACE_SYSCALL armed: when set, the tracee self-stops at every
    /// syscall entry + return, posts SIGTRAP, and waits for tracer
    /// wake via PTRACE_SYSCALL/CONT. Cleared and re-armed by the
    /// tracer (per-stop). Default false.
    pub ptrace_syscall_armed: AtomicBool,

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
}

/// POSIX credentials triple (real/effective/saved + fs* mirror), per
/// `13§5` and Linux `struct cred`. Supplementary groups stored inline
/// as a fixed-size array to avoid heap allocation in clone/fork.
/// `NGROUPS_V1 = 32` matches the small-process tail Linux historically
/// supported; raising the cap is a v2 extension.
#[repr(C)]
pub struct Creds {
    pub ruid:  AtomicU32,
    pub euid:  AtomicU32,
    pub suid:  AtomicU32,
    pub fsuid: AtomicU32,
    pub rgid:  AtomicU32,
    pub egid:  AtomicU32,
    pub sgid:  AtomicU32,
    pub fsgid: AtomicU32,
    pub ngroups: AtomicU32,
    pub groups:  UnsafeCell<[u32; Creds::NGROUPS_V1]>,

    /// Linux capability bitmasks (CAP_*). 64-bit for v3 layout
    /// per `capget(2)` / `capset(2)` and `capability.h`. Init = all
    /// bits set on root tasks; non-root inherits parent's. Real
    /// permission checks at privileged operations ride a follow-up;
    /// storage + capget/capset round-trip is the substrate.
    pub cap_effective:   AtomicU64,
    pub cap_permitted:   AtomicU64,
    pub cap_inheritable: AtomicU64,
    pub cap_ambient:     AtomicU64,
    pub cap_bounding:    AtomicU64,
}

impl Creds {
    pub const NGROUPS_V1: usize = 32;

    /// Initial creds for a fresh task — root, no supplementary groups.
    /// # C: O(1)
    pub const fn root() -> Self {
        Self {
            ruid: AtomicU32::new(0), euid: AtomicU32::new(0),
            suid: AtomicU32::new(0), fsuid: AtomicU32::new(0),
            rgid: AtomicU32::new(0), egid: AtomicU32::new(0),
            sgid: AtomicU32::new(0), fsgid: AtomicU32::new(0),
            ngroups: AtomicU32::new(0),
            groups: UnsafeCell::new([0u32; Self::NGROUPS_V1]),
            cap_effective:   AtomicU64::new(Self::CAP_FULL),
            cap_permitted:   AtomicU64::new(Self::CAP_FULL),
            cap_inheritable: AtomicU64::new(0),
            cap_ambient:     AtomicU64::new(0),
            cap_bounding:    AtomicU64::new(Self::CAP_FULL),
        }
    }

    /// All-bits-set bounding/permitted mask for v1 root tasks. Linux
    /// has ~40 capability bits defined; storing 64 leaves room for
    /// future additions and matches the v3 capset ABI shape exactly.
    pub const CAP_FULL: u64 = 0xFFFF_FFFF_FFFF_FFFF;

    /// Snapshot for fork/clone — copies every field including
    /// supplementary group list. Caller is the running parent task,
    /// preempt-off; child task is not yet scheduled (no concurrent
    /// reader on the new Creds).
    /// # SAFETY: caller holds the single-mutator invariant on `self`.
    /// # C: O(NGROUPS_V1)
    pub unsafe fn snapshot(&self) -> Self {
        use core::sync::atomic::Ordering::Relaxed;
        let out = Self {
            ruid:  AtomicU32::new(self.ruid.load(Relaxed)),
            euid:  AtomicU32::new(self.euid.load(Relaxed)),
            suid:  AtomicU32::new(self.suid.load(Relaxed)),
            fsuid: AtomicU32::new(self.fsuid.load(Relaxed)),
            rgid:  AtomicU32::new(self.rgid.load(Relaxed)),
            egid:  AtomicU32::new(self.egid.load(Relaxed)),
            sgid:  AtomicU32::new(self.sgid.load(Relaxed)),
            fsgid: AtomicU32::new(self.fsgid.load(Relaxed)),
            ngroups: AtomicU32::new(self.ngroups.load(Relaxed)),
            groups:  UnsafeCell::new([0u32; Self::NGROUPS_V1]),
            cap_effective:   AtomicU64::new(self.cap_effective.load(Relaxed)),
            cap_permitted:   AtomicU64::new(self.cap_permitted.load(Relaxed)),
            cap_inheritable: AtomicU64::new(self.cap_inheritable.load(Relaxed)),
            cap_ambient:     AtomicU64::new(self.cap_ambient.load(Relaxed)),
            cap_bounding:    AtomicU64::new(self.cap_bounding.load(Relaxed)),
        };
        // SAFETY: caller holds the single-mutator invariant; we just
        // built `out` and no other CPU has observed it yet, so writing
        // its `groups` UnsafeCell is sound.
        unsafe {
            let dst = &mut *out.groups.get();
            let src = &*self.groups.get();
            dst.copy_from_slice(src);
        }
        out
    }

    /// True when the effective uid is root (uid 0). Used by setuid
    /// permission checks: root may set ids freely; non-root may only
    /// transition between {ruid, euid, suid}.
    /// # C: O(1)
    pub fn is_root(&self) -> bool {
        self.euid.load(core::sync::atomic::Ordering::Acquire) == 0
    }

}

impl Task {
    /// True when this task holds capability `cap` in its effective
    /// set. Linux capability numbers per `task::cap` consts.
    /// # C: O(1)
    pub fn has_cap(&self, cap: u32) -> bool {
        self.creds.has_cap(cap)
    }
}

impl Creds {
    /// True when this Creds holds capability `cap` in its effective
    /// set. v1 single-bit check.
    /// # C: O(1)
    pub fn has_cap(&self, cap: u32) -> bool {
        if cap >= 64 { return false; }
        (self.cap_effective.load(core::sync::atomic::Ordering::Acquire) >> cap) & 1 == 1
    }
}

/// Linux capability numbers per `linux/capability.h`. Bit position in
/// `cap_effective` / `cap_permitted` / `cap_bounding` masks. v1
/// recognises every defined capability slot 0..40; unknowns return
/// false from `Creds::has_cap`.
pub mod cap {
    pub const CHOWN:            u32 = 0;
    pub const DAC_OVERRIDE:     u32 = 1;
    pub const DAC_READ_SEARCH:  u32 = 2;
    pub const FOWNER:           u32 = 3;
    pub const FSETID:           u32 = 4;
    pub const KILL:             u32 = 5;
    pub const SETGID:           u32 = 6;
    pub const SETUID:           u32 = 7;
    pub const SETPCAP:          u32 = 8;
    pub const LINUX_IMMUTABLE:  u32 = 9;
    pub const NET_BIND_SERVICE: u32 = 10;
    pub const NET_BROADCAST:    u32 = 11;
    pub const NET_ADMIN:        u32 = 12;
    pub const NET_RAW:          u32 = 13;
    pub const IPC_LOCK:         u32 = 14;
    pub const IPC_OWNER:        u32 = 15;
    pub const SYS_MODULE:       u32 = 16;
    pub const SYS_RAWIO:        u32 = 17;
    pub const SYS_CHROOT:       u32 = 18;
    pub const SYS_PTRACE:       u32 = 19;
    pub const SYS_PACCT:        u32 = 20;
    pub const SYS_ADMIN:        u32 = 21;
    pub const SYS_BOOT:         u32 = 22;
    pub const SYS_NICE:         u32 = 23;
    pub const SYS_RESOURCE:     u32 = 24;
    pub const SYS_TIME:         u32 = 25;
    pub const SYS_TTY_CONFIG:   u32 = 26;
    pub const MKNOD:            u32 = 27;
    pub const LEASE:            u32 = 28;
    pub const AUDIT_WRITE:      u32 = 29;
    pub const AUDIT_CONTROL:    u32 = 30;
    pub const SETFCAP:          u32 = 31;
    pub const MAC_OVERRIDE:     u32 = 32;
    pub const MAC_ADMIN:        u32 = 33;
    pub const SYSLOG:           u32 = 34;
    pub const WAKE_ALARM:       u32 = 35;
    pub const BLOCK_SUSPEND:    u32 = 36;
    pub const AUDIT_READ:       u32 = 37;
    pub const PERFMON:          u32 = 38;
    pub const BPF:              u32 = 39;
    pub const CHECKPOINT_RESTORE: u32 = 40;
}

/// Linux `struct sigaction` core fields per `27§3`. Stored
/// per-task at signal-1 indices.
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default)]
pub struct SaHandler {
    /// Handler entry. `0` = SIG_DFL (default disposition); `1` =
    /// SIG_IGN (ignore). Anything else = user fn pointer.
    pub handler:   u64,
    /// `SA_*` flags (Linux: SA_SIGINFO=0x4, SA_RESTART=0x10000000,
    /// SA_NOCLDSTOP, SA_NODEFER, etc.).
    pub flags:     u64,
    /// Optional return-trampoline (sa_restorer). musl + glibc set
    /// this to a libc-private stub that issues `rt_sigreturn`.
    pub restorer:  u64,
    /// Per-handler additional mask applied during dispatch.
    pub mask:      u64,
}

impl Task {
    /// Enqueue `info` on the per-task RT signal queue for `signo`
    /// (33..=64). Returns true if accepted, false if dropped due
    /// to the per-signal cap. Caller is also responsible for
    /// setting the pending bit on `sigpending`. Standard signals
    /// (1..=31) MUST NOT use this path — they collapse to the
    /// bitmap with synthesised siginfo at delivery time.
    /// # C: O(1)
    pub fn rt_push(&self, info: SigInfo) -> bool {
        let idx = match info.signo.checked_sub(33) {
            Some(i) if (i as usize) < 32 => i as usize,
            _ => return false,
        };
        let mut g = self.rt_sigqueue.lock();
        if g[idx].len() >= RT_QUEUE_CAP { return false; }
        g[idx].push_back(info);
        true
    }

    /// Pop the longest-waiting siginfo for RT `signo` (33..=64).
    /// Returns `None` if the queue is empty (i.e. the bitmap had
    /// the bit set without a queued record — synthesised by a
    /// non-`sigqueue` source like `kill(2)` — and the caller
    /// should fall back to a synthesised siginfo).
    /// `queue_empty_after` lets the caller decide whether to
    /// clear the bitmap bit (POSIX: bit clears when queue drains).
    /// # C: O(1)
    pub fn rt_pop(&self, signo: u32) -> (Option<SigInfo>, bool) {
        let idx = match signo.checked_sub(33) {
            Some(i) if (i as usize) < 32 => i as usize,
            _ => return (None, true),
        };
        let mut g = self.rt_sigqueue.lock();
        let info = g[idx].pop_front();
        let empty = g[idx].is_empty();
        (info, empty)
    }

    /// Borrow `mm` (the `Arc<AddressSpace>` if set). Read-only;
    /// callers must observe the single-mutator invariant per the
    /// `mm` field doc.
    /// # SAFETY: caller is in IRQ-off / preempt-off context, OR
    /// holds a guarantee that no concurrent execve runs against
    /// this task on another CPU.
    /// # C: O(1)
    pub unsafe fn mm_ref(&self) -> Option<&Arc<AddressSpace>> {
        // SAFETY: caller asserts no concurrent writer; UnsafeCell::get is the supported deref pattern for shared interior mutability under documented external synchronization.
        unsafe { (&*self.mm.get()).as_ref() }
    }

    /// Atomically replace `mm` with `new`, dropping the old Arc.
    /// Used by `execve` per `15§5` and `Task::new_user_with_mm`.
    /// # SAFETY: caller is the running task on its CPU OR holds
    /// the runqueue invariant for this task; preempt-off; single-
    /// CPU UP. Not safe to call on an actively-scheduled task from
    /// another CPU.
    /// # C: O(1) + Arc drop
    pub unsafe fn replace_mm(&self, new: Option<Arc<AddressSpace>>) {
        // SAFETY: see fn-level contract; single-mutator on this CPU.
        unsafe { *self.mm.get() = new; }
    }
}

/// POSIX `timer_create` slot per Linux `timer_create(2)`. Stored
/// inline on Task in a fixed-size array — N=8 timers per task is
/// enough for the v1 audience (systemd-service-timer, ssh keepalive).
/// Real waitqueue + cross-CPU signal-on-fire ride a follow-up; v1
/// fires from the syscall-return tail of the owning task.
#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct PosixTimer {
    /// Absolute monotonic-ns deadline. `0` means disarmed (or empty
    /// when `signo == 0`).
    pub deadline_ns: u64,
    /// Repeat interval. `0` = one-shot.
    pub interval_ns: u64,
    /// `sigev_value` from sigevent (passed into siginfo on fire).
    pub sigev_value: u64,
    /// Linux-side signal number (1..=64). `0` ⇒ slot is FREE.
    /// `signo != 0` + `deadline_ns == 0` ⇒ allocated but disarmed.
    pub signo: i32,
    /// Number of expirations missed since the last `timer_getoverrun`.
    pub overrun: u32,
    /// Clock id used at create time (CLOCK_REALTIME / CLOCK_MONOTONIC).
    pub clockid: u32,
    /// Padding to 8-byte alignment.
    pub _pad: u32,
}

impl PosixTimer {
    pub const SLOTS: usize = 8;
}

/// 8-byte-aligned byte buffer holding a per-arch HAL `Context`.
/// Per-arch Context types start with `rsp`/`sp` which are u64;
/// the explicit alignment keeps that field at offset 0 with
/// natural alignment regardless of the buffer placement.
#[repr(C, align(8))]
pub struct ArchCtxBuf(pub [u8; ARCH_CTX_SIZE]);

/// Opaque per-arch FPU/SIMD state buffer; per-arch crate casts to
/// FpuStateX86_64 / FpuStateAArch64. align(16) per FXSAVE / NEON
/// store-pair requirements.
#[repr(C, align(16))]
pub struct ArchFpuBuf(pub [u8; ARCH_FPU_SIZE]);

// SAFETY: `arch_ctx` mutation is gated by the kernel scheduler's
// runqueue invariant (only the CPU running this task writes the
// buffer, and only via `Context::switch` which is a single
// register-dance with no preempt window). Reads are likewise
// single-CPU per active-task invariant. AtomicPtr fields are
// inherently Sync.
unsafe impl Sync for Task {}

impl Task {
    /// Construct a new Runnable kernel-thread task (no `mm`). Tests
    /// use this; production allocation goes through
    /// `spawn_kernel_thread` once HAL `Context` is wired (`13§4`).
    /// # C: O(1)
    pub fn new(tid: u32, name: &'static str, class: SchedClass) -> Self {
        Self::new_with_mm(tid, name, class, None)
    }

    /// Construct a new Runnable user task with the given address
    /// space per `13§5`. Production user-task creation
    /// (clone3 / fork / execve) routes here.
    /// # C: O(1)
    pub fn new_user(
        tid: u32,
        name: &'static str,
        class: SchedClass,
        mm: Arc<AddressSpace>,
    ) -> Self {
        Self::new_with_mm(tid, name, class, Some(mm))
    }

    /// Internal constructor — both kthread and user paths funnel here.
    /// # C: O(1)
    fn new_with_mm(
        tid: u32,
        name: &'static str,
        class: SchedClass,
        mm: Option<Arc<AddressSpace>>,
    ) -> Self {
        Self {
            tid,
            tgid: AtomicU32::new(tid),
            name,
            state:    AtomicU8::new(TaskState::Runnable as u8),
            on_rq:    AtomicBool::new(false),
            cpu:      AtomicU16::new(u16::MAX),
            vruntime: AtomicU64::new(0),
            class,
            exit_status: AtomicI32::new(0),
            kernel_stack: AtomicPtr::new(core::ptr::null_mut()),
            arch_ctx: UnsafeCell::new(ArchCtxBuf([0u8; ARCH_CTX_SIZE])),
            mm: UnsafeCell::new(mm),
            stack: None,
            parent_tid: AtomicU32::new(0),
            pgid:       AtomicU32::new(tid),
            sid:        AtomicU32::new(tid),
            fd_table: UnsafeCell::new(None),
            sigpending: AtomicU64::new(0),
            rt_sigqueue: Spinlock::new([
                VecDeque::new(), VecDeque::new(), VecDeque::new(), VecDeque::new(),
                VecDeque::new(), VecDeque::new(), VecDeque::new(), VecDeque::new(),
                VecDeque::new(), VecDeque::new(), VecDeque::new(), VecDeque::new(),
                VecDeque::new(), VecDeque::new(), VecDeque::new(), VecDeque::new(),
                VecDeque::new(), VecDeque::new(), VecDeque::new(), VecDeque::new(),
                VecDeque::new(), VecDeque::new(), VecDeque::new(), VecDeque::new(),
                VecDeque::new(), VecDeque::new(), VecDeque::new(), VecDeque::new(),
                VecDeque::new(), VecDeque::new(), VecDeque::new(), VecDeque::new(),
            ]),
            sigmask:    AtomicU64::new(0),
            sigaltstack_sp:    AtomicU64::new(0),
            sigaltstack_size:  AtomicU64::new(0),
            sigaltstack_flags: AtomicU32::new(2 /* SS_DISABLE */),
            sigactions: UnsafeCell::new([SaHandler { handler: 0, flags: 0, restorer: 0, mask: 0 }; 64]),
            parent_arc: UnsafeCell::new(None),
            cmdline:    UnsafeCell::new(None),
            exe_path:   UnsafeCell::new(None),
            cwd:        UnsafeCell::new(alloc::string::String::from("/")),
            environ:    UnsafeCell::new(None),
            rlimits:    UnsafeCell::new([(u64::MAX, u64::MAX); 16]),
            nice:       AtomicI8::new(0),
            spawn_ns:   AtomicU64::new(0),
            cumulative_child_ns: AtomicU64::new(0),
            alarm_ns:   AtomicU64::new(0),
            alarm_interval_ns: AtomicU64::new(0),
            umask:      AtomicU32::new(0o022),
            clear_child_tid: AtomicU64::new(0),
            vfork_pending: AtomicBool::new(false),
            ns_membership: AtomicU64::new(0),
            uts_hostname:  UnsafeCell::new(alloc::string::String::new()),
            traced_by:       AtomicU32::new(0),
            ptrace_options:  AtomicU32::new(0),
            ptrace_eventmsg: AtomicU64::new(0),
            ptrace_siginfo:  Spinlock::new(None),
            landlock_chain:  Spinlock::new(alloc::vec::Vec::new()),
            fpu_state:       UnsafeCell::new(ArchFpuBuf([0u8; ARCH_FPU_SIZE])),
            ptrace_fpu_dirty: AtomicBool::new(false),
            singlestep:    AtomicU32::new(0),
            seccomp_filters: UnsafeCell::new(alloc::vec::Vec::new()),
            robust_list_head: AtomicU64::new(0),
            robust_list_len:  AtomicU64::new(0),
            posix_timers: UnsafeCell::new([PosixTimer::default(); PosixTimer::SLOTS]),
            no_new_privs:   AtomicBool::new(false),
            keep_caps:      AtomicBool::new(false),
            pdeathsig:      AtomicU32::new(0),
            child_subreaper: AtomicBool::new(false),
            personality:    AtomicU32::new(0),
            root:           UnsafeCell::new(alloc::string::String::from("/")),
            ipc_ns:         AtomicU64::new(0),
            net_ns:         AtomicU64::new(0),
            pid_ns:         AtomicU64::new(0),
            vtgid:          AtomicU32::new(0),
            vtid:           AtomicU32::new(0),
            unshare_pid_pending: AtomicBool::new(false),
            user_ns:        AtomicU64::new(0),
            parent_user_ns: AtomicU64::new(0),
            cgroup_ns:      AtomicU64::new(0),
            mount_ns:       AtomicU64::new(0),
            ptrace_syscall_armed: AtomicBool::new(false),
            rseq_ptr:       AtomicU64::new(0),
            rseq_len:       AtomicU32::new(0),
            rseq_sig:       AtomicU32::new(0),
            creds: Creds::root(),
        }
    }

    /// Borrow the fd table. Returns `None` for tasks without one
    /// (kthreads, idle).
    /// # SAFETY: caller is in IRQ-off / preempt-off context, OR
    /// holds a guarantee that no concurrent `replace_fd_table` runs
    /// against this task on another CPU.
    /// # C: O(1)
    pub unsafe fn fd_table_ref(&self) -> Option<&Arc<FdTable>> {
        // SAFETY: caller asserts no concurrent writer; UnsafeCell::get is the supported deref pattern under documented external synchronization.
        unsafe { (&*self.fd_table.get()).as_ref() }
    }

    /// Replace the fd table — used by `init` to install the
    /// boot console table, by fork to clone a parent's table,
    /// and by execve when CLOEXEC entries get cleared.
    /// # SAFETY: caller is the running task on this CPU OR holds
    /// the runqueue invariant for this task; preempt-off; UP.
    /// # C: O(1) + Arc drop
    pub unsafe fn replace_fd_table(&self, new: Option<Arc<FdTable>>) {
        // SAFETY: see fn-level contract; single-mutator on this CPU.
        unsafe { *self.fd_table.get() = new; }
    }

    /// Attach a kernel stack to this task. Stores the top-of-stack
    /// (one past the last byte) in `kernel_stack` and takes
    /// ownership of the backing `Box<[u8]>` so it stays alive for
    /// the task's lifetime.
    /// # SAFETY: caller is the spawn path; this `Task` is not yet
    /// scheduled (no concurrent reader of `kernel_stack`).
    /// # C: O(1)
    pub unsafe fn install_stack(&mut self, stack: Box<[u8]>) {
        let len = stack.len();
        self.stack = Some(stack);
        // Recompute top from the freshly stored Box. Borrowing
        // through `as_mut()` is sound because we just took ownership.
        let s = self.stack.as_mut().expect("just-stored");
        // SAFETY: `s.as_mut_ptr().add(len)` is the one-past-the-last
        // byte ptr — well-defined provenance per std slice semantics.
        let top = unsafe { s.as_mut_ptr().add(len) };
        self.kernel_stack.store(top, Ordering::Release);
    }

    /// Cast the opaque arch-context buffer to `*mut C` for a
    /// per-arch HAL `Context` type. Compile-time-asserts that
    /// `size_of::<C>() <= ARCH_CTX_SIZE`. Caller's responsibility
    /// to honour the single-mutator-per-active-CPU invariant.
    /// # SAFETY: caller is the kernel scheduler holding the
    /// runqueue invariant for this task; the returned pointer
    /// aliases `self.arch_ctx`'s storage and must not outlive a
    /// pending `Context::switch` against this task.
    /// # C: O(1)
    pub unsafe fn arch_ctx_ptr<C: Sized>(&self) -> *mut C {
        const { assert!(core::mem::size_of::<C>() <= ARCH_CTX_SIZE,
            "Context size exceeds ARCH_CTX_SIZE; bump the constant in `crates/sched`"); }
        self.arch_ctx.get() as *mut C
    }

    /// # C: O(1)
    pub fn state(&self) -> TaskState {
        TaskState::from_u8(self.state.load(Ordering::Acquire))
            .expect("Task::state corrupt")
    }

    /// CAS state transition. Returns `Ok(())` on success, `Err(current)`
    /// if the observed state didn't match `from`.
    /// # C: O(1)
    pub fn cas_state(&self, from: TaskState, to: TaskState) -> Result<(), TaskState> {
        match self.state.compare_exchange(
            from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire,
        ) {
            Ok(_)  => Ok(()),
            Err(v) => Err(TaskState::from_u8(v).expect("Task::cas_state corrupt")),
        }
    }

    /// # C: O(1)
    pub fn set_state(&self, s: TaskState) { self.state.store(s as u8, Ordering::Release); }

    /// Lift this task's vruntime to `floor` if it's currently below.
    /// Used when waking a long-sleeping CFS task into a moving RQ
    /// `min_vruntime` (`13§5` invariant 5).
    /// # C: O(1)
    pub fn lift_vruntime(&self, floor: u64) {
        let cur = self.vruntime.load(Ordering::Acquire);
        if cur < floor {
            self.vruntime.store(floor, Ordering::Release);
        }
    }
}
