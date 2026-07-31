// `pidfd_send_signal(2)`'s flag, scope and siginfo-forgery rules.
//
// UNGATED (CLAUDE.md phantom-test rule): the pidfd slot file itself is
// `#[cfg(target_os = "oxide-kernel")]`, so a test module inside it would never
// compile. Everything here is a pure decision over the syscall arguments.

use syscall::errno::Errno;

/// `PIDFD_SIGNAL_THREAD` — target the one thread the pidfd names.
pub const PIDFD_SIGNAL_THREAD: u32 = 1 << 0;
/// `PIDFD_SIGNAL_THREAD_GROUP` — target its whole process.
pub const PIDFD_SIGNAL_THREAD_GROUP: u32 = 1 << 1;
/// `PIDFD_SIGNAL_PROCESS_GROUP` — target its whole process group.
pub const PIDFD_SIGNAL_PROCESS_GROUP: u32 = 1 << 2;
/// `PIDFD_SEND_SIGNAL_FLAGS` — every accepted bit.
pub const PIDFD_SEND_SIGNAL_FLAGS: u32 =
    PIDFD_SIGNAL_THREAD | PIDFD_SIGNAL_THREAD_GROUP | PIDFD_SIGNAL_PROCESS_GROUP;

/// `PIDFD_SELF_THREAD` — the magic fd naming the CALLING THREAD, so a process
/// can signal itself without opening a pidfd (`include/uapi/linux/fcntl.h`).
pub const PIDFD_SELF_THREAD: i32 = -10000;
/// `PIDFD_SELF_THREAD_GROUP` — the magic fd naming the caller's thread group.
pub const PIDFD_SELF_THREAD_GROUP: i32 = -10001;

/// Which set of tasks the signal reaches.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Scope {
    /// `PIDTYPE_PID` — one thread's private pending set.
    Thread,
    /// `PIDTYPE_TGID` — the process' shared pending set.
    ThreadGroup,
    /// `PIDTYPE_PGID` — every process in the target's process group.
    ProcessGroup,
}

/// Where the pidfd argument points before any fd lookup happens.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Target {
    /// A real pidfd that must be resolved through the fd table.
    Fd(i32),
    /// `PIDFD_SELF_THREAD` / `PIDFD_SELF_THREAD_GROUP`; the `Scope` is the
    /// default the magic value implies before `flags` can override it.
    SelfTask(Scope),
}

/// Linux's flag validation: unknown bits are EINVAL, and at most ONE scope bit
/// may be set (`hweight32(flags & PIDFD_SEND_SIGNAL_FLAGS) > 1`).
/// # C: O(1)
pub fn validate_flags(flags: u32) -> Result<(), i64> {
    if flags & !PIDFD_SEND_SIGNAL_FLAGS != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    if (flags & PIDFD_SEND_SIGNAL_FLAGS).count_ones() > 1 {
        return Err(-(Errno::Einval.as_i32() as i64));
    }
    Ok(())
}

/// Decode the `pidfd` argument. # C: O(1)
pub fn classify_target(pidfd: i32) -> Target {
    match pidfd {
        PIDFD_SELF_THREAD => Target::SelfTask(Scope::Thread),
        PIDFD_SELF_THREAD_GROUP => Target::SelfTask(Scope::ThreadGroup),
        other => Target::Fd(other),
    }
}

/// The final scope. `flags` wins when it names one; otherwise the pidfd's own
/// kind decides — a `PIDFD_THREAD` (i.e. `O_EXCL`) pidfd is thread-scoped,
/// every other pidfd is process-scoped.
/// # C: O(1)
pub fn scope_for(flags: u32, default: Scope) -> Scope {
    match flags & PIDFD_SEND_SIGNAL_FLAGS {
        PIDFD_SIGNAL_THREAD => Scope::Thread,
        PIDFD_SIGNAL_THREAD_GROUP => Scope::ThreadGroup,
        PIDFD_SIGNAL_PROCESS_GROUP => Scope::ProcessGroup,
        _ => default,
    }
}

/// Linux's "only allow sending arbitrary signals to yourself" gate:
///
/// ```text
/// if ((task_pid(current) != pid || type > PIDTYPE_TGID) &&
///     (kinfo.si_code >= 0 || kinfo.si_code == SI_TKILL))
///         return -EPERM;
/// ```
///
/// `si_code >= 0` is the kernel-origin range and `SI_TKILL` is stamped by
/// `tkill`/`tgkill` themselves; forging either at another task would let a
/// process fabricate a kernel-generated signal. Note the `type > PIDTYPE_TGID`
/// clause: a PROCESS-GROUP send is never "yourself", even when the caller is in
/// that group.
/// # C: O(1)
pub fn siginfo_forgery_rejected(si_code: i32, targets_self: bool, scope: Scope) -> bool {
    let self_send = targets_self && scope != Scope::ProcessGroup;
    if self_send { return false; }
    si_code >= 0 || si_code == sched::signum::SI_TKILL
}

#[cfg(test)]
mod tests;
