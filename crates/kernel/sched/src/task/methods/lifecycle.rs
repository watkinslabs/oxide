#![allow(unused_imports)]
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{fence, AtomicBool, AtomicI8, AtomicI32, AtomicPtr, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};
#[cfg(feature = "debug-task-fpu-provenance")]
use core::sync::atomic::AtomicUsize;

use sync::Spinlock;
use vmm::AddressSpace;

use crate::ARCH_CTX_SIZE;

use super::super::{ArchCtxBuf, ArchFpuBuf, Creds, PendingWake, SigActions, SignalPending, SchedClass, SyscallSnapshot, Task, TaskCore, TaskSecurity, TaskState, WaitState};
#[cfg(feature = "debug-watchdog")]
use super::super::WakeDiagPhase;
use super::super::namespaces::TaskNamespaces;
use crate::signum::Signum;
#[cfg(feature = "debug-smp")]
use super::{task_canary_head, task_canary_tail};
#[cfg(any(feature = "debug-smp", feature = "debug-stack-guard"))]
use super::{TASK_STACK_GUARD, TASK_STACK_GUARD_BYTES, TASK_STACK_WATERMARK_OFF};

/// Linux `init_task.timer_slack_ns` / `default_timer_slack_ns` — 50 microseconds.
const DEFAULT_TIMER_SLACK_NS: u64 = 50_000;

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
        if let Some(mm) = mm.as_ref() { mm.mmget(); }
        let starts_in_user = mm.is_some();
        let pid = Arc::new(crate::pid::PidIdentity::new(tid));
        let thread_group = Arc::new(crate::thread_group::ThreadGroup::new(Arc::clone(&pid)));
        // Taken before the group is moved into the struct: every thread of a
        // process shares ONE signalfd readiness source (Linux
        // `sighand->signalfd_wqh`).
        let signalfd_poll = thread_group.signalfd_poll();
        let fpu_state = ArchFpuBuf::arch_default();
        #[cfg(feature = "debug-task-fpu-provenance")]
        let dbg_fpu_state_expected = fpu_state.debug_ptr_bits();
        Self {
            core: TaskCore {
                #[cfg(feature = "debug-smp")]
                dbg_canary_head: AtomicU64::new(task_canary_head(tid)),
                tid,
                tgid: AtomicU32::new(tid),
                nt_peb: AtomicU64::new(0),
                nt_teb: AtomicU64::new(0),
                nt_start_address: AtomicU64::new(0),
                nt_thread_ui_languages: Spinlock::new((0, alloc::vec::Vec::new())),
                nt_job_id: AtomicU64::new(0),
                pid,
                thread_group,
                name: Spinlock::new(Task::pack_spawn_name(name)),
                state:    AtomicU8::new(TaskState::Runnable as u8),
                on_rq:    AtomicBool::new(false),
                on_cpu:   AtomicBool::new(false),
                need_resched: AtomicBool::new(false),
                frozen:   AtomicBool::new(false),
                freeze_reasons: core::sync::atomic::AtomicU8::new(0),
                // Linux kthreads start with PF_NOFREEZE and opt in with
                // set_freezable(); userspace is freezable by default.
                nofreeze: AtomicBool::new(!starts_in_user),
                suspend_task: AtomicBool::new(false),
                nt_suspend_count: AtomicU32::new(0),
                yield_pending: AtomicBool::new(false),
                kthread_stop: AtomicBool::new(false),
                kthread_park: AtomicBool::new(false),
                kthread_parked: AtomicBool::new(false),
                kernel_thread: AtomicBool::new(!starts_in_user),
                kthread_result: AtomicI32::new(0),
                kthread_exited: AtomicBool::new(false),
                reaped:   AtomicBool::new(false),
                exiting:  AtomicBool::new(false),
                oom_score_adj: AtomicI32::new(0),
                oom_victim: AtomicBool::new(false),
                wake_next: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                on_wake_list: AtomicBool::new(false),
                cpu:      AtomicU16::new(u16::MAX),
                util_avg: AtomicU32::new(0),
                util_last_update_ns: AtomicU64::new(0),
                in_iowait: AtomicBool::new(false),
                vruntime: AtomicU64::new(0),
                exec_start_ns: AtomicU64::new(0),
                sum_exec_runtime_ns: AtomicU64::new(0),
                vtime_start_ns: AtomicU64::new(0),
                vtime_state: AtomicU8::new(if starts_in_user {
                    crate::cpustat::VTIME_USER
                } else {
                    crate::cpustat::VTIME_SYSTEM
                }),
                last_syscall_nr: AtomicU32::new(u32::MAX),
                nsyscalls: AtomicU64::new(0),
                syscall_snapshot: Spinlock::new(crate::task::SyscallSnapshot::default()),
                min_flt: AtomicU64::new(0),
                maj_flt: AtomicU64::new(0),
                nvcsw:   AtomicU64::new(0),
                nivcsw:  AtomicU64::new(0),
                nr_migrations: AtomicU64::new(0),
                #[cfg(feature = "debug-getdents")]
                getdents: crate::diag::getdents::GetdentsState::new(),
                #[cfg(feature = "debug-syscall-return")]
                syscall_return: crate::diag::syscall_return::SyscallReturnState::new(),
                io_rchar: AtomicU64::new(0),
                io_wchar: AtomicU64::new(0),
                io_syscr: AtomicU64::new(0),
                io_syscw: AtomicU64::new(0),
                io_read_bytes: AtomicU64::new(0),
                io_write_bytes: AtomicU64::new(0),
                io_cancelled_write_bytes: AtomicU64::new(0),
                futex_uaddr: AtomicU64::new(0),
                load_weight: AtomicU32::new(match class {
                    SchedClass::Normal { weight } => weight,
                    _ => crate::cputime::NICE_0_WEIGHT,
                }),
                mempolicy: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
                task_wake_lock: Spinlock::new(()),
                #[cfg(feature = "debug-watchdog")]
                wake_diag_phase: AtomicU8::new(WakeDiagPhase::None as u8),
                #[cfg(feature = "debug-watchdog")]
                wake_diag_ns: AtomicU64::new(0),
                cpus_allowed: cpu::AtomicCpuMask::all(),
                user_cpus_allowed: cpu::AtomicCpuMask::new(),
                cpuset_cpus_allowed: cpu::AtomicCpuMask::all(),
                no_setaffinity: AtomicBool::new(false),
                class_enc: AtomicU64::new(class.encode()),
                policy: AtomicU32::new(crate::sched_enc::policy_code_for(class)),
                sched_reset_on_fork: AtomicBool::new(false),
                sched_slice_ns: AtomicU64::new(0),
                uclamp_min: AtomicU32::new(0),
                uclamp_max: AtomicU32::new(crate::sched_enc::UCLAMP_CAPACITY_SCALE),
                uclamp_user_defined: AtomicU8::new(0),
                exit_status: AtomicI32::new(0),
                exit_signal: AtomicU8::new(Signum::Sigchld as u8),
                parent_tid: AtomicU32::new(0),
                forknoexec: AtomicBool::new(true),
                nproc_exceeded: AtomicBool::new(false),
                nproc_charged:  AtomicBool::new(false),
                ucounts_ns:     AtomicU64::new(0),
                ucounts_uid:    AtomicU32::new(0),
                used_superpriv: AtomicBool::new(false),
                rt_time_slice: AtomicU32::new(crate::sched_enc::RR_TIMESLICE_TICKS),
                dl: crate::deadline::DlEntity::new(),
                rt_requeue_tail: AtomicBool::new(false),
            },
            security: TaskSecurity {
                landlock_domain: Spinlock::new(None),
                // A thread with no address space has never run user code and
                // carries the kernel's own label; a user task starts in the
                // policy's init domain until an execve transitions it. `62§5`.
                selinux_label: Spinlock::new(if starts_in_user {
                    crate::selinux_label::TaskLabel::init()
                } else {
                    crate::selinux_label::TaskLabel::kernel()
                }),
                landlock_tsync_work: Spinlock::new(None),
                landlock_tsync_id: AtomicU64::new(0),
                landlock_log_state: AtomicU32::new(0),
                notify_signal: AtomicBool::new(false),
                fpu_state:       UnsafeCell::new(fpu_state),
                #[cfg(feature = "debug-task-fpu-provenance")]
                dbg_fpu_state_expected: AtomicUsize::new(dbg_fpu_state_expected),
                ptrace_fpu_dirty: AtomicBool::new(false),
                singlestep:    AtomicU32::new(0),
                nocpuid:       AtomicBool::new(false),
                iopl_emul:     core::sync::atomic::AtomicU8::new(0),
                io_bitmap:     Spinlock::new(None),
                tif_io_bitmap: AtomicBool::new(false),
                // POR_EL0 begins restrictive; a thread opens keys deliberately.
                #[cfg(target_arch = "aarch64")]
                pkey_rights:   AtomicU64::new(crate::pkey_rights::init_value()),
                shstk_features: AtomicU64::new(0),
                shstk_locked:   AtomicU64::new(0),
                #[cfg(target_arch = "aarch64")]
                svc_frame:     core::sync::atomic::AtomicU64::new(0),
                #[cfg(target_arch = "x86_64")]
                fault_frame:   AtomicU64::new(0),
                #[cfg(target_arch = "x86_64")]
                fault_rsp:     AtomicU64::new(0),
                #[cfg(target_arch = "x86_64")]
                fault_rip:     AtomicU64::new(0),
                seccomp_filters: Spinlock::new(alloc::vec::Vec::new()),
                seccomp_mode:    AtomicU8::new(0),
                robust_list_head: AtomicU64::new(0),
                robust_list_len:  AtomicU64::new(0),
                sysvsem_undo:     AtomicU64::new(0),
                pi_base_class: AtomicU64::new(u64::MAX),
                no_new_privs:   AtomicBool::new(false),
                tsc_sigsegv:    AtomicBool::new(false),
                tagged_addr:    AtomicBool::new(false),
                dumpable:       AtomicU8::new(super::super::SUID_DUMP_USER),
                thp_disable:    AtomicU8::new(super::super::THP_DISABLE_OFF),
                timer_slack_ns: AtomicU64::new(DEFAULT_TIMER_SLACK_NS),
                default_timer_slack_ns: AtomicU64::new(DEFAULT_TIMER_SLACK_NS),
                mce_kill:       AtomicU8::new(0),
                pdeathsig:      AtomicU32::new(0),
                io_flusher:     crate::prctl::io_flusher::IoFlusher::new(),
                syscall_dispatch: crate::prctl::sud::SyscallUserDispatch::new(),
                // Reconciled against the global registration state while the task
                // is published under REG; an unpublished task cannot enter a syscall.
                syscall_work: AtomicU32::new(0),
                personality:    AtomicU32::new(0),
                nt_personality: AtomicBool::new(false),
                net_namespace:  Spinlock::new(Some(network_namespace::initial())),
                vtgid:          AtomicU32::new(0),
                vtid:           AtomicU32::new(0),
                ptrace_syscall_armed: AtomicBool::new(false),
                ptrace_seized:   AtomicBool::new(false),
                ptrace_stop_rax: AtomicU64::new(0),
                stop_pending:    AtomicBool::new(false),
                cont_pending:    AtomicBool::new(false),
                stop_code:       AtomicU32::new(0),
                debugregs:       crate::debugreg::slab::Lazy::new(),
                #[cfg(target_arch = "aarch64")]
                hw_break: crate::debugreg::slab::Lazy::new(),
                jobctl:          AtomicU64::new(0),
                rseq_ptr:       AtomicU64::new(0),
                rseq_len:       AtomicU32::new(0),
                rseq_sig:       AtomicU32::new(0),
                rseq_ids:       AtomicU64::new(u64::MAX),
                rseq_slice_enabled: AtomicBool::new(false),
                rseq_slice_granted: AtomicBool::new(false),
                rseq_slice_expires_ns: AtomicU64::new(0),
                rseq_slice_yielded: AtomicBool::new(false),
                rseq_force_fixup: AtomicBool::new(false),
                creds: Creds::root(),
                audit_identity: AtomicU64::new(u64::MAX),
                #[cfg(feature = "debug-smp")]
                dbg_canary_tail: AtomicU64::new(task_canary_tail(tid)),
            },
            registered_rings: Spinlock::new(None),
            nt_callback_stack: Spinlock::new(crate::nt_callback::Stack::new()),
            nt_apc_queue: crate::nt_apc::Queue::new(),
            nt_activation_stack: Spinlock::new(crate::nt_activation::Stack::new()),
            nt_exception: crate::nt_exception::State::new(),
            kernel_stack: AtomicPtr::new(core::ptr::null_mut()),
            kernel_stack_memcg: AtomicU64::new(cgroup::NO_MEMCG),
            kernel_stack_charge_bytes: AtomicU64::new(0),
            arch_ctx: UnsafeCell::new(ArchCtxBuf([0u8; ARCH_CTX_SIZE])),
            mm: UnsafeCell::new(mm),
            mm_pin_lock: Spinlock::new(()),
            stack: Spinlock::new(None),
            fd_table: UnsafeCell::new(None),
            fd_table_pin_lock: Spinlock::new(()),
            sigpending: SignalPending::with_poll(signalfd_poll),
            sigqueue: Spinlock::new(core::array::from_fn(|_| VecDeque::new())),
            sigmask:    AtomicU64::new(0),
            saved_sigmask:   AtomicU64::new(0),
            restore_sigmask: core::sync::atomic::AtomicBool::new(false),
            sigaltstack_sp:    AtomicU64::new(0),
            sigaltstack_size:  AtomicU64::new(0),
            sigaltstack_flags: AtomicU32::new(2 /* SS_DISABLE */),
            sigactions: UnsafeCell::new(Arc::new(SigActions::new())),
            parent_arc: Spinlock::new(None),
            cmdline:    Spinlock::new(None),
            exe_path:   Spinlock::new(None),
            exe_inode:  Spinlock::new(None),
            fs_context: Spinlock::new(Arc::new(super::super::FsContext::new())),
            environ:    Spinlock::new(None),
            nice:       AtomicI8::new(0),
            io_context: Spinlock::new(crate::ioprio::IoContext::new(crate::ioprio::DEFAULT)),
            spawn_ns:   AtomicU64::new(0),
            start_boottime_ns: 0,
            wakeup_deadline_ns: AtomicU64::new(0),
            utime_ns:   AtomicU64::new(0),
            stime_ns:   AtomicU64::new(0),
            alarm_ns:   AtomicU64::new(0),
            alarm_interval_ns: AtomicU64::new(0),
            itimer_virtual_ns: AtomicU64::new(0),
            itimer_virtual_interval_ns: AtomicU64::new(0),
            itimer_prof_ns: AtomicU64::new(0),
            itimer_prof_interval_ns: AtomicU64::new(0),
            rt_timeout_ns: AtomicU64::new(0),
            clear_child_tid: AtomicU64::new(0),
            set_child_tid: AtomicU64::new(0),
            restart_block: super::super::restart::RestartBlock::new(),
            vfork_completion: Arc::new(crate::vfork_completion::VforkCompletion::new()),
            park_site: crate::park_site::ParkSite::new(),
            hung_last_switch_count: AtomicU64::new(0),
            hung_last_switch_ns: AtomicU64::new(0),
            namespaces:      Spinlock::new(Some(TaskNamespaces::initial())),
            traced_by:       AtomicU32::new(0),
            ptrace_options:  AtomicU32::new(0),
            ptrace_eventmsg: AtomicU64::new(0),
            ptrace_siginfo:  Spinlock::new(None),
            io_uring_filters: Spinlock::new(None),
            io_uring_restrict: Spinlock::new(None),
        }
    }

    /// Attach a kernel stack to this task. Stores the top-of-stack
    /// (one past the last byte) in `kernel_stack` and takes
    /// ownership of the backing `Box<[u8]>` so it stays alive for
    /// the task's lifetime.
    /// # SAFETY: caller is the spawn path; this `Task` is not yet
    /// scheduled (no concurrent reader of `kernel_stack`).
    /// # C: O(1)
    pub unsafe fn install_stack(&mut self) -> bool {
        self.debug_check_canary("install_stack");
        // C213: guard-paged kernel stack (Linux CONFIG_VMAP_STACK) — an
        // unmapped guard page below the 16 KiB stack turns an overflow into an
        // immediate #PF instead of a silent scribble of the adjacent block.
        // `mut` used only by the canary fill below (debug builds).
        #[cfg_attr(not(any(feature = "debug-smp", feature = "debug-stack-guard")), allow(unused_mut))]
        let mut stack = match crate::kstack::alloc() { Some(s) => s, None => return false };
        let top = stack.top();
        #[cfg(any(feature = "debug-smp", feature = "debug-stack-guard"))]
        {
            let s = stack.as_mut_slice();
            let guard_len = core::cmp::min(TASK_STACK_GUARD_BYTES, s.len());
            s[..guard_len].fill(TASK_STACK_GUARD);
            if s.len() >= TASK_STACK_WATERMARK_OFF + guard_len {
                s[TASK_STACK_WATERMARK_OFF..TASK_STACK_WATERMARK_OFF + guard_len]
                    .fill(TASK_STACK_GUARD);
            }
        }
        *self.stack.lock() = Some(stack);
        crate::kstack::note_owner(top, self.tid);
        self.kernel_stack.store(top, Ordering::Release);
        true
    }

    /// Release this task's kernel stack (Linux `put_task_stack`).
    ///
    /// Called from the context-switch tail once the task is off-CPU for the
    /// last time. A zombie has finished running, so it does not need its stack
    /// while it waits to be reaped, and holding it until the `Arc<Task>` drops
    /// both pins 16 KiB per unreaped child and makes reaping able to free a
    /// stack a task might still be running on.
    ///
    /// Idempotent: a second call, or one for a task that owns no stack, is a
    /// no-op. Clears `kernel_stack` with the storage so nothing can be resumed
    /// onto freed memory.
    /// # C: O(stack pages)
    /// # Lk: takes `stack` (leaf)
    /// # Ctx: any, with the owning task off-CPU
    pub fn release_kernel_stack(&self) {
        let released = self.stack.lock().take();
        if released.is_some() { self.kernel_stack.store(core::ptr::null_mut(), Ordering::Release); }
        drop(released);
    }

    /// Charge the already-installed stack before task publication. The
    /// allocating cgid remains fixed across later cgroup migration.
    /// # C: O(depth · subtree)
    pub fn try_charge_kernel_stack(&self, cgid: u64) -> bool {
        self.debug_check_canary("try_charge_kernel_stack");
        let bytes = match self.stack.lock().as_ref() { Some(stack) => stack.len() as u64, None => return true };
        if bytes == 0 || !cgroup::is_mounted() { return true; }
        if !cgroup::try_charge_memory(cgid, cgroup::MemoryKind::KernelStack, bytes) { return false; }
        if self.kernel_stack_memcg.compare_exchange(cgroup::NO_MEMCG, cgid, Ordering::AcqRel, Ordering::Acquire).is_err() {
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::KernelStack, bytes);
            return false;
        }
        self.kernel_stack_charge_bytes.store(bytes, Ordering::Release);
        true
    }

    /// Exact currently charged kernel-stack bytes. # C: O(1)
    pub fn kernel_stack_bytes(&self) -> u64 { self.kernel_stack_charge_bytes.load(Ordering::Acquire) }

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
        self.debug_check_canary("arch_ctx_ptr");
        const { assert!(core::mem::size_of::<C>() <= ARCH_CTX_SIZE,
            "Context size exceeds ARCH_CTX_SIZE; bump the constant in `crates/sched`"); }
        self.arch_ctx.get() as *mut C
    }
}
