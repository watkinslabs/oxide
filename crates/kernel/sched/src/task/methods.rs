use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicI8, AtomicI32, AtomicPtr, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

use sync::Spinlock;
use vfs::FdTable;
use vmm::AddressSpace;

use crate::ARCH_CTX_SIZE;

use super::{ArchCtxBuf, ArchFpuBuf, Creds, PosixTimer, SaHandler, SchedClass, Task, TaskState};

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
            on_cpu:   AtomicBool::new(false),
            frozen:   AtomicBool::new(false),
            cpu:      AtomicU16::new(u16::MAX),
            vruntime: AtomicU64::new(0),
            exec_start_ns: AtomicU64::new(0),
            sum_exec_runtime_ns: AtomicU64::new(0),
            last_syscall_nr: AtomicU32::new(u32::MAX),
            nsyscalls: AtomicU64::new(0),
            futex_uaddr: AtomicU64::new(0),
            load_weight: AtomicU32::new(match class {
                SchedClass::Normal { weight } => weight,
                _ => crate::cputime::NICE_0_WEIGHT,
            }),
            cpus_allowed: AtomicU64::new(u64::MAX),
            class_enc: AtomicU64::new(class.encode()),
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
            child_sigq: Spinlock::new(VecDeque::new()),
            sigmask:    AtomicU64::new(0),
            sigaltstack_sp:    AtomicU64::new(0),
            sigaltstack_size:  AtomicU64::new(0),
            sigaltstack_flags: AtomicU32::new(2 /* SS_DISABLE */),
            sigactions: UnsafeCell::new([SaHandler { handler: 0, flags: 0, restorer: 0, mask: 0 }; 64]),
            parent_arc: UnsafeCell::new(None),
            cmdline:    UnsafeCell::new(None),
            ctty:       UnsafeCell::new(None),
            exe_path:   UnsafeCell::new(None),
            cwd:        UnsafeCell::new(alloc::string::String::from("/")),
            cwd_vfs:    UnsafeCell::new(None),
            environ:    UnsafeCell::new(None),
            rlimits:    UnsafeCell::new(crate::rlimit::DEFAULT_RLIMITS),
            nice:       AtomicI8::new(0),
            ioprio:     AtomicU16::new(0),
            spawn_ns:   AtomicU64::new(0),
            wakeup_deadline_ns: AtomicU64::new(0),
            cumulative_child_ns: AtomicU64::new(0),
            alarm_ns:   AtomicU64::new(0),
            alarm_interval_ns: AtomicU64::new(0),
            umask:      AtomicU32::new(0o022),
            clear_child_tid: AtomicU64::new(0),
            vfork_pending: AtomicBool::new(false),
            ns_membership: AtomicU64::new(0),
            uts_ns:        AtomicU64::new(0),
            traced_by:       AtomicU32::new(0),
            ptrace_options:  AtomicU32::new(0),
            ptrace_eventmsg: AtomicU64::new(0),
            ptrace_siginfo:  Spinlock::new(None),
            landlock_chain:  Spinlock::new(alloc::vec::Vec::new()),
            fpu_state:       UnsafeCell::new(ArchFpuBuf::arch_default()),
            ptrace_fpu_dirty: AtomicBool::new(false),
            singlestep:    AtomicU32::new(0),
            #[cfg(target_arch = "aarch64")]
            svc_frame:     core::sync::atomic::AtomicU64::new(0),
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
            root_vfs:       UnsafeCell::new(None),
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
            stop_pending:    AtomicBool::new(false),
            cont_pending:    AtomicBool::new(false),
            stop_signal:     AtomicU8::new(0),
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

    /// PID-namespace-visible process id (`vtgid`, falling back to the real
    /// `tgid` when no NS virtualisation is active). This is the value Linux
    /// reports in `SCM_CREDENTIALS`/`SO_PEERCRED` (it delivers `pid_vnr`
    /// relative to the reader's NS) and via `getpid`. AF_UNIX credential
    /// stamping MUST use this, not the raw global `tgid`: PID 1 (systemd)
    /// tracks each service by its NS-local pid, so a notify datagram
    /// carrying the global tgid matches no unit and the service times out.
    /// # C: O(1)
    pub fn visible_pid(&self) -> u32 {
        let v = self.vtgid.load(Ordering::Acquire);
        if v != 0 { v } else { self.tgid.load(Ordering::Acquire) }
    }

    /// Lift this task's vruntime to `floor` if it's currently below;
    /// `13§5` invariant 5. F211: also see `set_vruntime_to_floor`.
    /// # C: O(1)
    pub fn lift_vruntime(&self, floor: u64) {
        let cur = self.vruntime.load(Ordering::Acquire);
        if cur < floor { self.vruntime.store(floor, Ordering::Release); }
    }
    /// F211 sleeper credit on wake (Linux place_entity).
    /// # C: O(1)
    pub fn set_vruntime_to_floor(&self, f: u64) { self.vruntime.store(f, Ordering::Release); }
}
