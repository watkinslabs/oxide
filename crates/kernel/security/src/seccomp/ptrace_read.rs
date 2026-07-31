// `PTRACE_SECCOMP_GET_FILTER` / `PTRACE_SECCOMP_GET_METADATA`'s side of
// seccomp — `seccomp_get_filter` / `seccomp_get_metadata` / `get_nth_filter`.
// The ptrace shim owns the user copies; the caller gate and the chain indexing
// are seccomp's own rules and live here.

use syscall::errno::Errno;

use super::flags::SECCOMP_FILTER_FLAG_LOG;
use super::uapi::*;
use super::entry::mode_of_current;

/// Linux's shared gate for both requests:
/// `if (!capable(CAP_SYS_ADMIN) || current->seccomp.mode != SECCOMP_MODE_DISABLED)
/// return -EACCES;`
///
/// The second half matters as much as the first: a tracer that is ITSELF
/// seccomp-confined must not be able to read out the filters confining it (or
/// its tracee), whatever capabilities it holds.
/// # C: O(1)
pub fn filter_read_allowed(cap_sys_admin: bool) -> Result<(), Errno> {
    if !cap_sys_admin { return Err(Errno::Eacces); }
    if mode_of_current() != SECCOMP_MODE_DISABLED { return Err(Errno::Eacces); }
    Ok(())
}

/// `get_nth_filter(task, filter_off)` — index the task's chain from the
/// NEWEST filter backwards, which is the order Linux's `filter->prev` walk
/// produces: offset 0 is the most recently installed one.
///
/// A task not in `SECCOMP_MODE_FILTER` is EINVAL (not ENOENT) even when its
/// chain happens to be empty, and an offset past the end is ENOENT.
/// # C: O(N_filters)
pub fn nth_filter(task: &sched::Task, filter_off: u64)
    -> Result<alloc::vec::Vec<u64>, Errno>
{
    let (prog, _) = nth(task, filter_off)?;
    Ok(prog)
}

/// The install-time flags `PTRACE_SECCOMP_GET_METADATA` reports. Linux
/// publishes exactly one bit — `SECCOMP_FILTER_FLAG_LOG` — so the record
/// cannot leak flags a future kernel might add meaning to.
/// # C: O(N_filters)
pub fn nth_filter_flags(task: &sched::Task, filter_off: u64) -> Result<u64, Errno> {
    let (_, flags) = nth(task, filter_off)?;
    Ok(flags & SECCOMP_FILTER_FLAG_LOG)
}

fn nth(task: &sched::Task, filter_off: u64)
    -> Result<(alloc::vec::Vec<u64>, u64), Errno>
{
    use core::sync::atomic::Ordering;
    if task.seccomp_mode.load(Ordering::Acquire) as u32 != SECCOMP_MODE_FILTER {
        return Err(Errno::Einval);
    }
    let chain = task.seccomp_filters.lock();
    let count = chain.len() as u64;
    if filter_off >= count { return Err(Errno::Enoent); }
    // `count -= filter_off; for (filter = orig; count > 1; filter = filter->prev)`
    // walks BACK from the newest, so offset 0 names the last installed filter.
    let idx = (count - 1 - filter_off) as usize;
    let f = &chain[idx];
    Ok((f.prog.clone(), f.flags))
}

#[cfg(test)]
#[path = "ptrace_read/tests.rs"] mod tests;
