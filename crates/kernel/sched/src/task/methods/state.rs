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

use super::super::{ArchCtxBuf, ArchFpuBuf, Creds, PendingWake, SigActions, SignalPending, SchedClass, SyscallSnapshot, Task, TaskState, WaitState};
#[cfg(feature = "debug-watchdog")]
use super::super::WakeDiagPhase;
use super::super::namespaces::TaskNamespaces;
use crate::signum::Signum;

impl Task {
    /// # C: O(1)
    pub fn state(&self) -> TaskState {
        self.debug_check_canary("state");
        TaskState::from_u8(self.state.load(Ordering::Acquire))
            .expect("Task::state corrupt")
    }

    /// Linux `/proc` and task-dump state character, including the sleep class.
    /// # C: O(1)
    pub fn linux_state_char(&self) -> u8 {
        self.debug_check_canary("linux_state_char");
        let raw = self.state.load(Ordering::Acquire);
        let state = TaskState::from_u8(raw).expect("Task::linux_state_char corrupt");
        if matches!(state, TaskState::Sleeping)
            && !matches!(WaitState::from_state_bits(raw), WaitState::Interruptible)
        {
            b'D'
        } else {
            state.linux_char()
        }
    }

    /// Long-form Linux `/proc` state label, including the sleep class.
    /// # C: O(1)
    pub fn linux_status_label(&self) -> &'static str {
        self.debug_check_canary("linux_status_label");
        let raw = self.state.load(Ordering::Acquire);
        let state = TaskState::from_u8(raw).expect("Task::linux_status_label corrupt");
        if matches!(state, TaskState::Sleeping)
            && !matches!(WaitState::from_state_bits(raw), WaitState::Interruptible)
        {
            "D (disk sleep)"
        } else {
            state.linux_status_label()
        }
    }

    /// CAS state transition. Returns `Ok(())` on success, `Err(current)`
    /// if the observed state didn't match `from`.
    /// # C: O(1)
    pub fn cas_state(&self, from: TaskState, to: TaskState) -> Result<(), TaskState> {
        self.debug_check_canary("cas_state");
        let mut seen = self.state.load(Ordering::Acquire);
        loop {
            let current = TaskState::from_u8(seen).expect("Task::cas_state corrupt");
            if current != from { return Err(current); }
            if self.state.compare_exchange_weak(seen, to as u8, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                return Ok(());
            }
            seen = self.state.load(Ordering::Acquire);
        }
    }

    /// Complete a wake claim after its destination activation has been
    /// committed.  The waker owns the interim Waking state, so schedule never
    /// independently requeues the switching-out task.
    /// # C: O(1)
    pub fn complete_wake(&self) {
        let _ = self.cas_state(TaskState::Waking, TaskState::Runnable);
        #[cfg(feature = "debug-watchdog")]
        self.wake_diag_phase.store(WakeDiagPhase::None as u8, Ordering::Release);
    }

    /// Record a diagnostic-only wake-placement milestone.  The timestamp is
    /// published before its phase so a task dump that sees a phase also sees
    /// the age for that same or a later milestone.
    #[cfg(feature = "debug-watchdog")]
    /// # C: O(1)
    pub fn wake_diag_mark(&self, phase: WakeDiagPhase, now_ns: u64) {
        self.wake_diag_ns.store(now_ns, Ordering::Release);
        self.wake_diag_phase.store(phase as u8, Ordering::Release);
    }

    /// Atomically publish both `TASK_*` wake mask and Sleeping lifecycle
    /// state.  Linux keeps these in one state word so a signal waker cannot
    /// observe a sleeping task with a stale mask.
    /// # C: O(1)
    pub fn set_sleep_state(&self, state: WaitState) {
        self.state.store(TaskState::Sleeping as u8 | state.state_bits(), Ordering::Release);
        // A sleep publication must order before the waiter's subsequent
        // condition recheck.  A release store alone permits Store->Load
        // reordering on weakly ordered SMP CPUs, letting both sides miss the
        // event.  The paired wake claim uses AcqRel CAS.
        fence(Ordering::SeqCst);
    }

    /// Snapshot the sleep mask encoded in the task-state word.
    /// # C: O(1)
    pub fn sleep_wait_state(&self) -> WaitState {
        WaitState::from_state_bits(self.state.load(Ordering::Acquire))
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

}


