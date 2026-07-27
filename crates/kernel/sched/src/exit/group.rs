// `do_group_exit` (Linux `kernel/exit.c`): the exit code every thread of the
// group reports, no matter which thread asked for the group death and no
// matter which signal actually killed the others.
//
//     if (sig->flags & SIGNAL_GROUP_EXIT)
//             exit_code = sig->group_exit_code;
//     else { ... sig->group_exit_code = exit_code;
//             sig->flags = SIGNAL_GROUP_EXIT;
//             zap_other_threads(current); }
//
// The latch is what makes `exit_group(N)` from a NON-leader thread report N:
// the leader is killed by the SIGKILL `zap_other_threads` posts, reaches its
// own fatal-signal path, calls `do_group_exit(SIGKILL)` — and finds the latch
// already holding N, so it exits with N instead of "killed by signal 9".
// Without the latch the parent's `waitpid` sees `WIFSIGNALED`/`SIGKILL` for
// every multi-threaded `exit_group`, and a fatal `SIGSEGV` in a worker thread
// is reported to the parent as `SIGKILL` rather than `SIGSEGV`.

/// Outcome of one `do_group_exit` arbitration.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GroupExit {
    /// Status EVERY thread of the group exits with (internal encoding).
    pub status: i32,
    /// This caller won the latch and therefore owns `zap_other_threads`.
    pub zap: bool,
}

/// Linux `do_group_exit` arbitration. `latched` is the group's
/// `SIGNAL_GROUP_EXIT`/`group_exit_code` pair (`None` when unset).
/// # C: O(1)
pub const fn arbitrate(latched: Option<i32>, requested: i32) -> GroupExit {
    match latched {
        Some(status) => GroupExit { status, zap: false },
        None         => GroupExit { status: requested, zap: true },
    }
}

/// `synchronize_group_exit`: the LAST thread of a group latches its own code
/// when nothing latched one before it, so a plain `exit(2)` by the final
/// thread still publishes through `group_exit_code`. A non-final thread's
/// plain `exit(2)` latches nothing — the group survives it.
/// # C: O(1)
pub const fn final_thread_latch(latched: Option<i32>, is_last_thread: bool, status: i32) -> Option<i32> {
    if latched.is_some() || !is_last_thread { None } else { Some(status) }
}
