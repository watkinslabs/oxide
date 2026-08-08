// Install-time gate for `seccomp(2)` / `prctl(PR_SET_SECCOMP)`, in exact
// check order: flag validation, then user-filter preparation, then filter
// preparation/attach.
//
// UNGATED (`CLAUDE.md` phantom-test rule): this is the permission ladder, so
// it must be reachable from `cargo test`.

use syscall::errno::Errno;

use super::flags::*;
use super::uapi::*;

/// Everything the install decision reads, gathered by the caller so the
/// decision itself is pure.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InstallCtx {
    pub flags: u64,
    /// `sock_fprog::len`, already copied in (a faulting copy is EFAULT and
    /// never reaches here).
    pub len: usize,
    /// `task_no_new_privs(current)`.
    pub no_new_privs: bool,
    /// `ns_capable_noaudit(current_user_ns(), CAP_SYS_ADMIN)` — the NOAUDIT
    /// form, which must NOT latch `PF_SUPERPRIV` on the task.
    pub cap_sys_admin: bool,
    /// `current->seccomp.mode` before the install.
    pub cur_mode: u32,
}

/// The checks that run BEFORE the filter body is copied and verified.
///
/// Order is load-bearing and matches Linux exactly:
///   1. `flags & ~SECCOMP_FILTER_FLAG_MASK` and the two flag-combination
///      rules -> EINVAL, before the `sock_fprog` is even read.
///   2. `fprog->len == 0 || fprog->len > BPF_MAXINSNS` -> EINVAL.
///   3. `!task_no_new_privs(current) && !ns_capable_noaudit(CAP_SYS_ADMIN)`
///      -> EACCES. Without this ANY unprivileged task can install a filter,
///      which is how an unprivileged process affects the behaviour of a
///      privileged child it later execs.
/// # C: O(1)
pub fn pre_verify_gate(c: &InstallCtx) -> Result<(), Errno> {
    validate_filter_flags(c.flags)?;
    if c.len == 0 || c.len > BPF_MAXINSNS { return Err(Errno::Einval); }
    if !c.no_new_privs && !c.cap_sys_admin { return Err(Errno::Eacces); }
    Ok(())
}

/// `MAX_INSNS_PER_PATH` — `(1 << 18) / sizeof(struct
/// sock_filter)`, the cap on the TOTAL instruction count of a task's whole
/// filter chain. Without it a task installs 4096-instruction filters until
/// every syscall walks megabytes of cBPF.
pub const MAX_INSNS_PER_PATH: usize = (1 << 18) / super::uapi::SOCK_FILTER_BYTES as usize;
/// `walker->prog->len + 4` — the per-already-installed-filter penalty
/// `seccomp_attach_filter` adds when it totals the chain.
pub const FILTER_PENALTY_INSNS: usize = 4;

/// `total_insns > MAX_INSNS_PER_PATH` -> ENOMEM. `existing` already carries
/// the per-filter penalty; the NEW filter is counted without one.
/// # C: O(1)
pub fn total_insns_exceeded(existing: usize, new_len: usize) -> bool {
    existing.saturating_add(new_len) > MAX_INSNS_PER_PATH
}

/// `seccomp_may_assign_mode` — once `current->seccomp.mode` is non-zero it
/// may only be re-assigned to ITSELF. A STRICT task cannot become a FILTER
/// task, a FILTER task cannot become STRICT, and a task already latched
/// `SECCOMP_MODE_DEAD` can become neither.
/// # C: O(1)
pub fn may_assign_mode(cur_mode: u32, new_mode: u32) -> bool {
    cur_mode == SECCOMP_MODE_DISABLED || cur_mode == new_mode
}

/// The post-verify half of the ladder, run once the program is known good.
/// # C: O(1)
pub fn post_verify_gate(c: &InstallCtx) -> Result<(), Errno> {
    if !may_assign_mode(c.cur_mode, SECCOMP_MODE_FILTER) { return Err(Errno::Einval); }
    Ok(())
}

/// `SECCOMP_FILTER_FLAG_NEW_LISTENER` asks the kernel to hand back a
/// notification fd and makes every `SECCOMP_RET_USER_NOTIF` from the new
/// filter block on a supervisor's reply. That transport is NOT built here
/// (no `seccomp_notif` anon-fd, no notify waitqueue), so the install FAILS
/// rather than returning a filter the caller believes is supervised while
/// its `RET_USER_NOTIF` silently ENOSYS-es.
/// # C: O(1)
pub fn listener_unsupported(flags: u64) -> Option<Errno> {
    if flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0 { Some(Errno::Enosys) } else { None }
}

/// `SECCOMP_GET_ACTION_AVAIL` — the action word the caller passed is either
/// one of the eight defined actions (0) or EOPNOTSUPP.
/// # C: O(1)
pub fn action_avail(action: u32) -> Result<(), Errno> {
    match action {
        SECCOMP_RET_KILL_PROCESS | SECCOMP_RET_KILL_THREAD | SECCOMP_RET_TRAP
        | SECCOMP_RET_ERRNO | SECCOMP_RET_USER_NOTIF | SECCOMP_RET_TRACE
        | SECCOMP_RET_LOG | SECCOMP_RET_ALLOW => Ok(()),
        _ => Err(Errno::Eopnotsupp),
    }
}
