// Task / SchedClass / TaskState definitions for the runqueue. Mirrors
// the spec's `13§5` shape. `mm` is now real (P2-13a integrates with
// `vmm::AddressSpace` for per-task address spaces). The other Arc'd
// payloads (`fd_table`, `sig`, `creds`, `ns`, `cgroup`) land with
// their consumer subsystems.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI8, AtomicI32, AtomicPtr, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

use vfs::FdTable;
use vmm::AddressSpace;

use crate::ARCH_CTX_SIZE;

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

    /// Opaque storage for the per-arch HAL `Context` (per `14§5.2`/
    /// `14§6.2`). Sized to `ARCH_CTX_SIZE`. Aligned on a u64 so the
    /// arch-specific Context's first field (an `rsp` / `sp`) sits
    /// at a natural-alignment offset. Caller (kernel) gates access
    /// with the runqueue invariant; see struct doc-comment.
    pub arch_ctx: UnsafeCell<ArchCtxBuf>,

    /// Per-task user address space per `13§5` / `11§3`. `None` for
    /// kernel-only threads (kthreads run in the kernel's static
    /// page tables). Shared via `Arc` per `clone3` semantics so
    /// `CLONE_VM` siblings share the same VMA tree (`13§5` field
    /// list). Schedule per `13§8`: switch_address_space called only
    /// when `next.mm != prev.mm`.
    ///
    /// Wrapped in `UnsafeCell` so `execve` (P2-21) can replace it
    /// in-place: the running task is the sole writer, and reads
    /// from `schedule()`'s AS-swap branch happen with preempt-off
    /// on the same CPU — single-mutator-per-active-CPU per `13§5`
    /// (same invariant the `arch_ctx` field relies on).
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
    /// [-20, 19]; 0 default. Fork inherits. The scheduler currently
    /// ignores it (CFS weight is fixed); v1 stores for visibility
    /// via getpriority + /proc/<pid>/stat field 19.
    pub nice: AtomicI8,

    /// Monotonic ns at task spawn. getrusage / times / proc stat
    /// utime are computed as `monotonic_ns() - spawn_ns`. `0` for
    /// hosted-test tasks where `Task::new` is the constructor.
    pub spawn_ns: AtomicU64,

    /// alarm(2)/setitimer ITIMER_REAL deadline in monotonic ns.
    /// `0` = no alarm pending. Dispatch tail compares against
    /// monotonic_ns() and posts SIGALRM (signal 14) when reached.
    pub alarm_ns: AtomicU64,

    /// ITIMER_REAL period in ns. `0` = one-shot. When the deadline
    /// fires, dispatch tail re-arms `alarm_ns = now + interval` if
    /// non-zero. setitimer(0) sets; getitimer(0) reads.
    pub alarm_interval_ns: AtomicU64,

    /// Per-task umask per POSIX umask(2). Default 0o022. Fork
    /// inherits. AND-NOT with creation mode in sys_open(O_CREAT)
    /// once we honor mode bits; v1 stores for getter visibility.
    pub umask: AtomicU32,

    /// CLONE_CHILD_CLEARTID address per `set_tid_address(2)`. Linux
    /// stores the user pointer; on thread exit, writes 0 to the
    /// addr + FUTEX_WAKE_PRIVATE. v1 stores for visibility; no
    /// per-thread cleanup in the single-thread model.
    pub clear_child_tid: AtomicU64,

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

    /// Tracer tid for `ptrace(2)` — 0 = no tracer attached. v1 honors
    /// PTRACE_TRACEME (child sets traced_by=parent_tid). The full
    /// PTRACE_ATTACH/SINGLESTEP/PEEK/POKE/SYSCALL surface lands with
    /// debugger-frontend integration in a v2 phase 22 follow-up.
    pub traced_by: AtomicU32,

    /// Set by PTRACE_SINGLESTEP, cleared by the trap handler after a
    /// single instruction has retired in user mode. While set, the
    /// kernel-to-user resume path arms the per-arch single-step bit
    /// (RFLAGS.TF on x86_64, MDSCR_EL1.SS + SPSR.SS on aarch64) so
    /// the next user instruction traps and the kernel posts SIGTRAP.
    /// # C: O(1)
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
        }
    }

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

/// 8-byte-aligned byte buffer holding a per-arch HAL `Context`.
/// Per-arch Context types start with `rsp`/`sp` which are u64;
/// the explicit alignment keeps that field at offset 0 with
/// natural alignment regardless of the buffer placement.
#[repr(C, align(8))]
pub struct ArchCtxBuf(pub [u8; ARCH_CTX_SIZE]);

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
            alarm_ns:   AtomicU64::new(0),
            alarm_interval_ns: AtomicU64::new(0),
            umask:      AtomicU32::new(0o022),
            clear_child_tid: AtomicU64::new(0),
            ns_membership: AtomicU64::new(0),
            uts_hostname:  UnsafeCell::new(alloc::string::String::new()),
            traced_by:     AtomicU32::new(0),
            singlestep:    AtomicU32::new(0),
            seccomp_filters: UnsafeCell::new(alloc::vec::Vec::new()),
            robust_list_head: AtomicU64::new(0),
            robust_list_len:  AtomicU64::new(0),
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
