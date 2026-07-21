use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI8, AtomicI32, AtomicPtr, AtomicU16, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use sync::Spinlock;
use vfs::FdTable;
use vmm::AddressSpace;

use crate::ARCH_CTX_SIZE;

use super::{ArchCtxBuf, ArchFpuBuf, Creds, PendingWake, PosixTimer, SigActions, SignalPending, SchedClass, Task, TaskState};
use super::namespaces::TaskNamespaces;
use crate::signum::Signum;

#[cfg(feature = "debug-smp")]
const TASK_CANARY_HEAD: u64 = 0x5441_534b_4845_4144;
#[cfg(feature = "debug-smp")]
const TASK_CANARY_TAIL: u64 = 0x5441_534b_5441_494c;
#[cfg(feature = "debug-smp")]
const TASK_STACK_GUARD: u8 = 0xa5;
#[cfg(feature = "debug-smp")]
const TASK_STACK_GUARD_BYTES: usize = 32;
#[cfg(feature = "debug-smp")]
const TASK_STACK_WATERMARK_OFF: usize = 16 * 1024;

#[cfg(feature = "debug-smp")]
#[inline]
fn task_canary_head(tid: u32) -> u64 {
    TASK_CANARY_HEAD ^ ((tid as u64) << 32) ^ tid as u64
}

#[cfg(feature = "debug-smp")]
#[inline]
fn task_canary_tail(tid: u32) -> u64 {
    TASK_CANARY_TAIL ^ ((tid as u64) << 17) ^ ((tid as u64) << 1)
}

/// Snapshot the architectural stack pointer without creating another Rust
/// frame.  This is diagnostic-only: when a stack guard is damaged, it tells
/// us whether the CPU is actually executing in that allocation or whether an
/// unrelated write overlapped it.
#[cfg(all(feature = "debug-smp", target_arch = "aarch64"))]
#[inline]
fn debug_stack_pointer() -> usize {
    let sp: usize;
    // SAFETY: reads the architectural SP register only; no memory or flags
    // are changed.  AArch64 permits `mov <gpr>, sp` at EL1.
    unsafe { core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags)); }
    sp
}

#[cfg(all(feature = "debug-smp", target_arch = "aarch64"))]
#[inline]
fn debug_frame_pointer() -> usize {
    let fp: usize;
    // SAFETY: reads x29 only; see `debug_stack_pointer`.
    unsafe { core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack, preserves_flags)); }
    fp
}

#[cfg(all(feature = "debug-smp", not(target_arch = "aarch64")))]
#[inline]
fn debug_frame_pointer() -> usize { 0 }

#[cfg(all(feature = "debug-smp", not(target_arch = "aarch64")))]
#[inline]
fn debug_stack_pointer() -> usize { 0 }

impl Task {
    /// Join an existing thread group while this task is still unpublished.
    /// # C: O(1)
    pub fn join_thread_group(&mut self, group: Arc<crate::thread_group::ThreadGroup>) {
        self.pid.join_group();
        self.thread_group = group;
    }

    /// Debug-smp Task lifetime sentinel. Trips when a stale `Task*` is used after
    /// its allocation was freed/reused, before the later victim object faults.
    /// # C: O(1)
    #[cfg(feature = "debug-smp")]
    #[track_caller]
    pub fn debug_check_canary(&self, site: &'static str) {
        let eh = task_canary_head(self.tid);
        let et = task_canary_tail(self.tid);
        let gh = self.dbg_canary_head.load(Ordering::Acquire);
        let gt = self.dbg_canary_tail.load(Ordering::Acquire);
        if gh != eh || gt != et {
            klog::write_raw(b"[TASK-CANARY site=");
            klog::write_raw(site.as_bytes());
            klog::write_raw(b" ptr=");
            klog::write_hex_u64(self as *const Task as u64);
            klog::write_raw(b" tid=");
            klog::write_dec_u64(self.tid as u64);
            klog::write_raw(b" tid_addr=");
            klog::write_hex_u64((&self.tid as *const u32) as u64);
            klog::write_raw(b" ctx_addr=");
            klog::write_hex_u64(self.arch_ctx.get() as u64);
            klog::write_raw(b" head=");
            klog::write_hex_u64(gh);
            klog::write_raw(b" tail=");
            klog::write_hex_u64(gt);
            klog::write_raw(b"]\n");
        }
        hal::kassert!(gh == eh && gt == et, "Task canary corrupted");
        if let Some(stack) = self.stack.as_ref() {
            let guard_len = core::cmp::min(TASK_STACK_GUARD_BYTES, stack.len());
            let watermark_live = stack.len() >= TASK_STACK_WATERMARK_OFF + guard_len
                && stack[TASK_STACK_WATERMARK_OFF..TASK_STACK_WATERMARK_OFF + guard_len]
                    .iter().any(|&b| b != TASK_STACK_GUARD);
            let mut i = 0usize;
            while i < guard_len && stack[i] == TASK_STACK_GUARD {
                i += 1;
            }
            if i != guard_len {
                let sp = debug_stack_pointer();
                let fp = debug_frame_pointer();
                let caller = core::panic::Location::caller();
                let stack_lo = stack.as_ptr() as usize;
                let stack_hi = stack_lo.saturating_add(stack.len());
                let sp_in_stack = sp >= stack_lo && sp < stack_hi;
                klog::write_raw(b"[TASK-STACK-GUARD site=");
                klog::write_raw(site.as_bytes());
                klog::write_raw(b" task=");
                klog::write_hex_u64(self as *const Task as u64);
                klog::write_raw(b" tid=");
                klog::write_dec_u64(self.tid as u64);
                klog::write_raw(b" stack=");
                klog::write_hex_u64(stack_lo as u64);
                klog::write_raw(b" stack_hi=");
                klog::write_hex_u64(stack_hi as u64);
                klog::write_raw(b" sp=");
                klog::write_hex_u64(sp as u64);
                klog::write_raw(b" fp=");
                klog::write_hex_u64(fp as u64);
                klog::write_raw(b" sp_in_stack=");
                klog::write_dec_u64(sp_in_stack as u64);
                klog::write_raw(b" caller_line=");
                klog::write_dec_u64(caller.line() as u64);
                klog::write_raw(b" offset=");
                klog::write_dec_u64(i as u64);
                klog::write_raw(b" crossed_16k=");
                klog::write_dec_u64(watermark_live as u64);
                klog::write_raw(b"]\n");
                panic!("Task kernel stack underflow");
            }
        }
    }

    /// # C: O(1)
    #[cfg(not(feature = "debug-smp"))]
    #[inline]
    pub fn debug_check_canary(&self, _site: &'static str) {}

    /// Validate the boxed FP/SIMD save-area identity before raw asm or ptrace
    /// access. Reading only the Box representation is deliberate: it lets the
    /// diagnostic reject a corrupt pointer before Rust or the architecture code
    /// dereferences it.
    /// # C: O(1)
    #[cfg(feature = "debug-task-fpu-provenance")]
    pub fn debug_check_fpu_state(&self, site: &'static str) {
        let expected = self.dbg_fpu_state_expected.load(Ordering::Acquire);
        // SAFETY: this reads the pointer-sized Box representation from the
        // task-owned UnsafeCell without dereferencing the candidate address;
        // scheduler/ptrace serialization prevents a concurrent field mutation.
        let actual = unsafe { core::ptr::read(self.fpu_state.get().cast::<usize>()) };
        let align = ArchFpuBuf::debug_alignment();
        let valid = actual == expected && actual != 0 && actual & (align - 1) == 0;
        if !valid {
            klog::write_raw(b"[TASK-FPU-PROVENANCE site=");
            klog::write_raw(site.as_bytes());
            klog::write_raw(b" task=");
            klog::write_hex_u64(self as *const Task as u64);
            klog::write_raw(b" tid=");
            klog::write_dec_u64(self.tid as u64);
            klog::write_raw(b" expected=");
            klog::write_hex_u64(expected as u64);
            klog::write_raw(b" actual=");
            klog::write_hex_u64(actual as u64);
            klog::write_raw(b" last_syscall=");
            klog::write_dec_u64(self.last_syscall_nr.load(Ordering::Acquire) as u64);
            klog::write_raw(b"]\n");
        }
        hal::kassert!(valid, "Task FPU state pointer corrupted");
    }

    /// # C: O(1)
    #[cfg(not(feature = "debug-task-fpu-provenance"))]
    #[inline]
    pub fn debug_check_fpu_state(&self, _site: &'static str) {}

    /// Process name for a task dump / procfs `comm`: the basename of the exec'd
    /// path (Linux sets `comm` from the invoked program at execve), falling back
    /// to the fork-time `name` before the first exec — so `ps` / `/proc/<pid>/
    /// comm` / a wedge task-dump show the REAL process (e.g. `systemd-journald`)
    /// instead of the generic fork-time `fork-child`. # C: O(path_len)
    pub fn comm(&self) -> alloc::string::String {
        use alloc::string::String;
        // SAFETY: the mm slot + `exe_path` mirror are single-mutator per `13§5`;
        // this is a snapshot read (diagnostic / procfs), matching
        // `proclink::task_exe_path`'s exe resolution.
        let exe = unsafe { self.mm_ref() }.and_then(|mm| mm.exe_path())
            .or_else(|| unsafe { (*self.exe_path.get()).clone() });
        match exe {
            Some(p) if !p.is_empty() => {
                let base = p.rsplit('/').next().unwrap_or(p.as_str());
                String::from(if base.is_empty() { self.name } else { base })
            }
            _ => String::from(self.name),
        }
    }

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
        let pid = Arc::new(crate::pid::PidIdentity::new(tid));
        let thread_group = Arc::new(crate::thread_group::ThreadGroup::new(Arc::clone(&pid)));
        let fpu_state = ArchFpuBuf::arch_default();
        #[cfg(feature = "debug-task-fpu-provenance")]
        let dbg_fpu_state_expected = fpu_state.debug_ptr_bits();
        Self {
            #[cfg(feature = "debug-smp")]
            dbg_canary_head: AtomicU64::new(task_canary_head(tid)),
            tid,
            tgid: AtomicU32::new(tid),
            pid,
            thread_group,
            name,
            state:    AtomicU8::new(TaskState::Runnable as u8),
            on_rq:    AtomicBool::new(false),
            on_cpu:   AtomicBool::new(false),
            frozen:   AtomicBool::new(false),
            yield_pending: AtomicBool::new(false),
            reaped:   AtomicBool::new(false),
            oom_score_adj: AtomicI32::new(0),
            oom_victim: AtomicBool::new(false),
            cpu:      AtomicU16::new(u16::MAX),
            vruntime: AtomicU64::new(0),
            exec_start_ns: AtomicU64::new(0),
            sum_exec_runtime_ns: AtomicU64::new(0),
            last_syscall_nr: AtomicU32::new(u32::MAX),
            nsyscalls: AtomicU64::new(0),
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
            cpus_allowed: AtomicU64::new(u64::MAX),
            class_enc: AtomicU64::new(class.encode()),
            exit_status: AtomicI32::new(0),
            exit_signal: AtomicU8::new(Signum::Sigchld as u8),
            kernel_stack: AtomicPtr::new(core::ptr::null_mut()),
            kernel_stack_memcg: AtomicU64::new(cgroup::NO_MEMCG),
            kernel_stack_charge_bytes: AtomicU64::new(0),
            arch_ctx: UnsafeCell::new(ArchCtxBuf([0u8; ARCH_CTX_SIZE])),
            mm: UnsafeCell::new(mm),
            mm_pin_lock: Spinlock::new(()),
            stack: None,
            parent_tid: AtomicU32::new(0),
            pgid:       AtomicU32::new(tid),
            sid:        AtomicU32::new(tid),
            fd_table: UnsafeCell::new(None),
            sigpending: SignalPending::new(),
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
            child_sigq: Spinlock::new(VecDeque::new()),
            sigmask:    AtomicU64::new(0),
            sigaltstack_sp:    AtomicU64::new(0),
            sigaltstack_size:  AtomicU64::new(0),
            sigaltstack_flags: AtomicU32::new(2 /* SS_DISABLE */),
            sigactions: UnsafeCell::new(Arc::new(SigActions::new())),
            parent_arc: UnsafeCell::new(None),
            cmdline:    UnsafeCell::new(None),
            ctty:       UnsafeCell::new(None),
            exe_path:   UnsafeCell::new(None),
            fs_context: Spinlock::new(Arc::new(super::FsContext::new())),
            environ:    UnsafeCell::new(None),
            rlimits:    UnsafeCell::new(crate::rlimit::DEFAULT_RLIMITS),
            nice:       AtomicI8::new(0),
            ioprio:     AtomicU16::new(0),
            spawn_ns:   AtomicU64::new(0),
            start_boottime_ns: 0,
            wakeup_deadline_ns: AtomicU64::new(0),
            cumulative_child_ns: AtomicU64::new(0),
            utime_ns:   AtomicU64::new(0),
            stime_ns:   AtomicU64::new(0),
            cumulative_child_utime_ns: AtomicU64::new(0),
            cumulative_child_stime_ns: AtomicU64::new(0),
            alarm_ns:   AtomicU64::new(0),
            alarm_interval_ns: AtomicU64::new(0),
            itimer_virtual_ns: AtomicU64::new(0),
            itimer_virtual_interval_ns: AtomicU64::new(0),
            itimer_prof_ns: AtomicU64::new(0),
            itimer_prof_interval_ns: AtomicU64::new(0),
            umask:      AtomicU32::new(0o022),
            clear_child_tid: AtomicU64::new(0),
            vfork_pending: AtomicBool::new(false),
            namespaces:      Spinlock::new(Some(TaskNamespaces::initial())),
            traced_by:       AtomicU32::new(0),
            ptrace_options:  AtomicU32::new(0),
            ptrace_eventmsg: AtomicU64::new(0),
            ptrace_siginfo:  Spinlock::new(None),
            landlock_chain:  Spinlock::new(alloc::vec::Vec::new()),
            fpu_state:       UnsafeCell::new(fpu_state),
            #[cfg(feature = "debug-task-fpu-provenance")]
            dbg_fpu_state_expected: AtomicUsize::new(dbg_fpu_state_expected),
            ptrace_fpu_dirty: AtomicBool::new(false),
            singlestep:    AtomicU32::new(0),
            #[cfg(target_arch = "aarch64")]
            svc_frame:     core::sync::atomic::AtomicU64::new(0),
            seccomp_filters: UnsafeCell::new(alloc::vec::Vec::new()),
            robust_list_head: AtomicU64::new(0),
            robust_list_len:  AtomicU64::new(0),
            posix_timers: UnsafeCell::new([PosixTimer::default(); PosixTimer::SLOTS]),
            no_new_privs:   AtomicBool::new(false),
            pdeathsig:      AtomicU32::new(0),
            child_subreaper: AtomicBool::new(false),
            personality:    AtomicU32::new(0),
            net_namespace:  Spinlock::new(Some(network_namespace::initial())),
            vtgid:          AtomicU32::new(0),
            vtid:           AtomicU32::new(0),
            ptrace_syscall_armed: AtomicBool::new(false),
            stop_pending:    AtomicBool::new(false),
            cont_pending:    AtomicBool::new(false),
            stop_signal:     AtomicU8::new(0),
            rseq_ptr:       AtomicU64::new(0),
            rseq_len:       AtomicU32::new(0),
            rseq_sig:       AtomicU32::new(0),
            creds: Creds::root(),
            #[cfg(feature = "debug-smp")]
            dbg_canary_tail: AtomicU64::new(task_canary_tail(tid)),
        }
    }

    /// Borrow the fd table. Returns `None` for tasks without one
    /// (kthreads, idle).
    /// # SAFETY: caller is in IRQ-off / preempt-off context, OR
    /// holds a guarantee that no concurrent `replace_fd_table` runs
    /// against this task on another CPU.
    /// # C: O(1)
    pub unsafe fn fd_table_ref(&self) -> Option<&Arc<FdTable>> {
        self.debug_check_canary("fd_table_ref");
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
        self.debug_check_canary("replace_fd_table");
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
        self.debug_check_canary("install_stack");
        let len = stack.len();
        self.stack = Some(stack);
        #[cfg(feature = "debug-smp")]
        {
            let s = self.stack.as_mut().expect("just-stored");
            let guard_len = core::cmp::min(TASK_STACK_GUARD_BYTES, s.len());
            s[..guard_len].fill(TASK_STACK_GUARD);
            if s.len() >= TASK_STACK_WATERMARK_OFF + guard_len {
                s[TASK_STACK_WATERMARK_OFF..TASK_STACK_WATERMARK_OFF + guard_len]
                    .fill(TASK_STACK_GUARD);
            }
        }
        // Recompute top from the freshly stored Box. Borrowing
        // through `as_mut()` is sound because we just took ownership.
        let s = self.stack.as_mut().expect("just-stored");
        // SAFETY: `s.as_mut_ptr().add(len)` is the one-past-the-last
        // byte ptr — well-defined provenance per std slice semantics.
        let top = unsafe { s.as_mut_ptr().add(len) };
        self.kernel_stack.store(top, Ordering::Release);
    }

    /// Charge the already-installed stack before task publication. The
    /// allocating cgid remains fixed across later cgroup migration.
    /// # C: O(depth · subtree)
    pub fn try_charge_kernel_stack(&self, cgid: u64) -> bool {
        self.debug_check_canary("try_charge_kernel_stack");
        let bytes = match self.stack.as_ref() { Some(stack) => stack.len() as u64, None => return true };
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

    /// # C: O(1)
    pub fn state(&self) -> TaskState {
        self.debug_check_canary("state");
        TaskState::from_u8(self.state.load(Ordering::Acquire))
            .expect("Task::state corrupt")
    }

    /// CAS state transition. Returns `Ok(())` on success, `Err(current)`
    /// if the observed state didn't match `from`.
    /// # C: O(1)
    pub fn cas_state(&self, from: TaskState, to: TaskState) -> Result<(), TaskState> {
        self.debug_check_canary("cas_state");
        match self.state.compare_exchange(
            from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire,
        ) {
            Ok(_)  => Ok(()),
            Err(v) => Err(TaskState::from_u8(v).expect("Task::cas_state corrupt")),
        }
    }

    /// Claim exclusive ownership of a sleeping task's wake placement. A
    /// failed claim is always a stale or racing wake; only the winner may add
    /// the task to a runqueue or deferred wake list. # C: O(1)
    pub fn claim_wake(&self) -> bool {
        self.cas_state(TaskState::Sleeping, TaskState::Runnable).is_ok()
    }

    /// Resolve a claimed deferred wake against the draining CPU's current task.
    /// The current-task case is owned by `schedule()`'s state check; a different
    /// executing task must remain deferred until `on_cpu` clears. # C: O(1)
    pub fn pending_wake(&self, current: *mut Task) -> PendingWake {
        if self.on_rq.load(Ordering::Acquire) { return PendingWake::Drop; }
        if !self.on_cpu.load(Ordering::Acquire) { return PendingWake::Ready; }
        if core::ptr::eq(self as *const Task, current as *const Task) {
            PendingWake::Drop
        } else {
            PendingWake::Defer
        }
    }

    /// # C: O(1)
    pub fn set_state(&self, s: TaskState) {
        self.debug_check_canary("set_state");
        self.state.store(s as u8, Ordering::Release);
    }

    /// PID-namespace-visible process id (`vtgid`, falling back to the real
    /// `tgid` when no NS virtualisation is active). This is the value Linux
    /// reports in `SCM_CREDENTIALS`/`SO_PEERCRED` (it delivers `pid_vnr`
    /// relative to the reader's NS) and via `getpid`. AF_UNIX credential
    /// stamping MUST use this, not the raw global `tgid`: PID 1 (systemd)
    /// tracks each service by its NS-local pid, so a notify datagram
    /// carrying the global tgid matches no unit and the service times out.
    /// # C: O(1)
    pub fn visible_pid(&self) -> u32 {
        self.debug_check_canary("visible_pid");
        let v = self.vtgid.load(Ordering::Acquire);
        if v != 0 { v } else { self.tgid.load(Ordering::Acquire) }
    }

    /// Linux `add_rchar(current, ret)` + `inc_syscr(current)` after vfs_read. # C: O(1)
    pub fn account_read_result(&self, ret: i64) {
        self.debug_check_canary("account_read_result");
        if ret >= 0 {
            self.io_rchar.fetch_add(ret as u64, Ordering::Relaxed);
        }
        self.io_syscr.fetch_add(1, Ordering::Relaxed);
    }

    /// Linux `add_wchar(current, ret)` + `inc_syscw(current)` after vfs_write. # C: O(1)
    pub fn account_write_result(&self, ret: i64) {
        self.debug_check_canary("account_write_result");
        if ret >= 0 {
            self.io_wchar.fetch_add(ret as u64, Ordering::Relaxed);
        }
        self.io_syscw.fetch_add(1, Ordering::Relaxed);
    }

    /// Lift this task's vruntime to `floor` if it's currently below;
    /// `13§5` invariant 5. F211: also see `set_vruntime_to_floor`.
    /// # C: O(1)
    pub fn lift_vruntime(&self, floor: u64) {
        self.debug_check_canary("lift_vruntime");
        let cur = self.vruntime.load(Ordering::Acquire);
        if cur < floor { self.vruntime.store(floor, Ordering::Release); }
    }
    /// F211 sleeper credit on wake (Linux place_entity).
    /// # C: O(1)
    pub fn set_vruntime_to_floor(&self, f: u64) {
        self.debug_check_canary("set_vruntime_to_floor");
        self.vruntime.store(f, Ordering::Release);
    }
}
