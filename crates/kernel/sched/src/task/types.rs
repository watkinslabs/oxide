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
