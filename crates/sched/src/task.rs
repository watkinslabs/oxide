// Task / SchedClass / TaskState definitions for the runqueue. Mirrors
// the spec's `13§5` shape minus the cross-cutting `Arc` payloads
// (`mm`, `fd_table`, `sig`, `creds`, `ns`, `cgroup`) which depend on
// subsystems not yet implemented. Those land alongside their consumers
// (vmm AS already exists; vfs FdTable, signal, etc. are upcoming).
//
// `kernel_stack` + `context: ArchContext` are also out — they require
// HAL `Context` (`14§4`); the runqueue logic itself doesn't need them.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU16, AtomicU64, AtomicU8, Ordering};

use hal::Pfn; // unused placeholder; keeps the dep graph stable when AddressSpace lands here

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
}

/// `13§5` task descriptor — runqueue-relevant fields only.
///
/// Allocation: heap-managed via `Arc<Task>` for v1; replaced by
/// slab-backed allocation per `12§3.2` once the integration lands. The
/// runqueue stores `Arc<Task>` clones and re-keys CFS by the current
/// `vruntime` snapshot on each insert.
pub struct Task {
    pub tid:  u32,
    pub name: &'static str,

    pub state:    AtomicU8,
    pub on_rq:    AtomicBool,
    pub cpu:      AtomicU16,
    pub vruntime: AtomicU64,
    pub class:    SchedClass,

    pub exit_status: AtomicI32,

    /// Placeholder for future `mm: Arc<AddressSpace>`.
    _mm_phantom: core::marker::PhantomData<Pfn>,
}

impl Task {
    /// Construct a new Runnable task. Tests use this; production
    /// allocation goes through `spawn_kernel_thread` once HAL `Context`
    /// is wired (`13§4`).
    /// # C: O(1)
    pub fn new(tid: u32, name: &'static str, class: SchedClass) -> Self {
        Self {
            tid,
            name,
            state:    AtomicU8::new(TaskState::Runnable as u8),
            on_rq:    AtomicBool::new(false),
            cpu:      AtomicU16::new(u16::MAX),
            vruntime: AtomicU64::new(0),
            class,
            exit_status: AtomicI32::new(0),
            _mm_phantom: core::marker::PhantomData,
        }
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
