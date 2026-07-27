// Task rlimit accessors. The table itself lives on the shared `ThreadGroup`
// (Linux `signal_struct.rlim`), so every thread of a process reads and writes
// ONE table; these are the per-task entry points that resolve to it
// (`docs/53` hollow-shell owner: sched).

use super::Task;
use crate::rlimit::{PrlimitError, check_new_rlimit, rlim};

impl Task {
    /// Linux `kernel/sys.c do_prlimit(tsk, resource, new_rlim, old_rlim)` — the
    /// single work-fn behind BOTH `getrlimit(2)`/`setrlimit(2)` (slots 97/160)
    /// and `prlimit64(2)` (slot 302). Returns the PREVIOUS `(cur, max)`, which
    /// Linux copies out only when the whole ladder passed:
    ///
    /// ```text
    /// if (resource >= RLIM_NLIMITS)                     return -EINVAL;
    /// if (new_rlim) { cur > max                         -> -EINVAL
    ///                 NOFILE && max > sysctl_nr_open    -> -EPERM }
    /// task_lock(tsk->group_leader);
    /// if (new_rlim && new->rlim_max > rlim->rlim_max && !capable(CAP_SYS_RESOURCE))
    ///                                                   retval = -EPERM;
    /// if (!retval) { *old_rlim = *rlim; *rlim = *new_rlim; }
    /// task_unlock(tsk->group_leader);
    /// ```
    ///
    /// `cap_sys_resource` is Linux's `capable(CAP_SYS_RESOURCE)` — deliberately
    /// the INIT user namespace check, not `ns_capable`: the upstream comment
    /// says "Keep the capable check against init_user_ns until cgroups can
    /// contain all limits". Lowering the hard limit is unprivileged and
    /// irreversible; raising it is not.
    ///
    /// The read-decide-write sequence runs under the thread group's rlimit lock
    /// so two threads racing `setrlimit` cannot both observe the old hard limit
    /// and both raise it.
    /// # C: O(1); # Lk: TaskList (thread group, momentary)
    pub fn do_prlimit(&self, resource: usize, new: Option<(u64, u64)>,
        cap_sys_resource: bool) -> Result<(u64, u64), PrlimitError>
    {
        if resource >= rlim::COUNT { return Err(PrlimitError::Einval); }
        if let Some(new) = new {
            check_new_rlimit(resource, new, vfs::fdtable::nr_open() as u64)?;
        }
        let mut table = self.thread_group.rlimits.lock();
        let old = table[resource];
        if let Some(new) = new {
            if new.1 > old.1 && !cap_sys_resource { return Err(PrlimitError::Eperm); }
            table[resource] = new;
        }
        Ok(old)
    }

    /// Read one `RLIMIT_*` slot (Linux `task_rlimit`). Out-of-range indices are
    /// rejected by the syscall shim before reaching here.
    /// # C: O(1); # Lk: TaskList (thread group, momentary)
    pub fn rlimit(&self, idx: usize) -> (u64, u64) {
        self.thread_group.rlimits.lock()[idx]
    }

    /// Write one `RLIMIT_*` slot for the whole thread group.
    /// # C: O(1); # Lk: TaskList (thread group, momentary)
    pub fn set_rlimit(&self, idx: usize, pair: (u64, u64)) {
        self.thread_group.rlimits.lock()[idx] = pair;
    }

    /// Snapshot the whole rlimit table (fork inheritance, `/proc/<pid>/limits`).
    /// # C: O(1); # Lk: TaskList (thread group, momentary)
    pub fn all_rlimits(&self) -> [(u64, u64); rlim::COUNT] {
        *self.thread_group.rlimits.lock()
    }

    /// Replace the whole rlimit table — `copy_signal`'s fork inheritance, run on
    /// an unpublished child that already owns its own `ThreadGroup`.
    /// # C: O(1); # Lk: TaskList (thread group, momentary)
    pub fn set_all_rlimits(&self, all: [(u64, u64); rlim::COUNT]) {
        *self.thread_group.rlimits.lock() = all;
    }
}
