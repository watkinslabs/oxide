//! Per-task security, tracing, restartable-sequence, and architecture policy state.

use super::*;

pub struct TaskSecurity {
    pub landlock_domain: Spinlock<Option<alloc::sync::Arc<landlock::Domain>>, TaskListClass>,
    /// Mandatory-access-control label: the domain this task runs in, the
    /// labels staged for its next create/exec operations, and the domain it
    /// came from. Stored by value because a SID is a handle into the policy's
    /// table, not a reference to a policy object — the tables are replaced
    /// under running tasks and the handle stays meaningful. Rules in
    /// `crate::selinux_label`.
    pub selinux_label: Spinlock<crate::selinux_label::TaskLabel, TaskListClass>,
    /// Linux `task_struct::task_works` subset used by Landlock TSYNC.  The
    /// target thread takes and executes this work on its own return-to-user
    /// path; a foreign CPU never writes that thread's credentials directly.
    pub landlock_tsync_work:
        Spinlock<Option<alloc::sync::Arc<crate::landlock_tsync::Transaction>>, TaskListClass>,
    /// Transaction generation already enrolled on this task.  It remains
    /// stamped after the work starts so the initiator's repeated thread-group
    /// scans cannot enqueue the same task twice.
    pub landlock_tsync_id: AtomicU64,
    /// Landlock denial-reporting state for this thread, packed into one word:
    /// the low bits name the layer levels THIS execution enforced, and the top
    /// bit records that some enforcement asked the layers beneath it to stay
    /// silent. Both are per-thread, not per-domain — the first is cleared by
    /// `execve` and the second survives an enforcement that installs no layer
    /// at all — which is why they cannot live on the immutable domain.
    /// Layout and reads live in `landlock::logging`.
    pub landlock_log_state: AtomicU32,
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

    /// Emulated x86 IOPL (`iopl(2)`), 0-3. Level 3 permits every I/O port;
    /// 0-2 permit none. Per-THREAD and inherited across fork.
    ///
    /// EMULATED, not the EFLAGS IOPL field: a real IOPL=3 would also let user
    /// mode run `cli`/`sti` and wedge the machine. The port grant is published
    /// through the TSS permit-everything window instead, which is exactly the
    /// grant `iopl(3)` promises and nothing more.
    pub iopl_emul: core::sync::atomic::AtomicU8,

    /// This thread's `ioperm(2)` port permission map, or `None` when it holds
    /// no per-port grant. Shared by reference with forked children until one
    /// of them edits it (`Arc::make_mut`), matching the reference's refcounted
    /// bitmap. Logic lives in `crate::ioport`.
    pub io_bitmap: Spinlock<Option<Arc<crate::ioport::IoBitmap>>, TaskListClass>,

    /// The reference's `TIF_IO_BITMAP`: true when this thread holds ANY port
    /// grant (`iopl_emul == 3` or a map). Recomputed from those two wherever
    /// either changes; it exists so the context-switch path decides in a
    /// single relaxed load whether the TSS window needs touching at all.
    pub tif_io_bitmap: AtomicBool,

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
    /// Recoverable x86 fault frame preserved while this task is descheduled.
    #[cfg(target_arch = "x86_64")]
    pub fault_frame: AtomicU64,
    #[cfg(target_arch = "x86_64")]
    pub fault_rsp: AtomicU64,
    #[cfg(target_arch = "x86_64")]
    pub fault_rip: AtomicU64,
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
    /// Native Windows/NT execution personality. Separate from Linux's
    /// `personality(2)` word so Linux ABI flags cannot select NT routing.
    pub nt_personality: AtomicBool,


    /// Owned network namespace membership. `None` after task exit releases
    /// membership, even while a pidfd keeps this `Task` allocation alive.
    pub(crate) net_namespace: Spinlock<Option<NetworkNamespaceRef>, Namespace>,

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
    pub stop_pending: AtomicBool,
    pub cont_pending: AtomicBool,
    pub stop_code: AtomicU32,
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
    /// A restartable-sequence fixup this thread owes for a reason OTHER than
    /// losing the CPU: `MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ` must abort a
    /// critical section on every target whether or not the barrier happened to
    /// preempt it. Set by the barrier IPI, consumed by the return-to-user path.
    pub rseq_force_fixup: AtomicBool,

    /// POSIX credentials per `13§5` / docs/14 cred-ABI block.
    /// Real ruid/euid/suid + fsuid mirror; same triple for gid.
    /// Init starts as root (all zero). fork copies, execve preserves.
    /// Single-mutator: the running task on this CPU is the sole writer
    /// (setuid family runs on the calling task only).
    pub creds: Creds,
    /// Login uid (high word) and audit session id (low word), published as one
    /// snapshot so a record cannot pair identities from two login writes.
    pub audit_identity: AtomicU64,
    #[cfg(feature = "debug-smp")]
    pub dbg_canary_tail: AtomicU64,
}

impl Deref for Task {
    type Target = TaskCore;

    fn deref(&self) -> &Self::Target { &self.core }
}

impl DerefMut for Task {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.core }
}
