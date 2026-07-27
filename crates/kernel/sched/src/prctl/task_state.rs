// Per-task `prctl(2)` state options — Linux `kernel/sys.c`.
//
// Every `PR_GET_*` that reports through a user pointer here uses
// `uaccess::copy_to_user`, so a bad pointer is EFAULT exactly as Linux's
// `put_user` makes it. Writing "best effort, skip on a bad pointer" instead
// hands userspace a success with an untouched buffer — the caller then reads
// whatever was on its stack and believes it.

use core::sync::atomic::Ordering;
use syscall::errno::Errno;

use super::decide;
use super::uapi::*;
use crate::task::Task;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Linux `put_user(v, (int __user *)arg2)`. # C: O(1)
fn put_user_i32(ptr: u64, v: i32) -> i64 {
    match uaccess::copy_to_user(ptr, &v.to_ne_bytes()) { Ok(()) => 0, Err(e) => err(e) }
}

/// Linux `put_user(v, (unsigned int __user *)adr)`. # C: O(1)
fn put_user_u32(ptr: u64, v: u32) -> i64 {
    match uaccess::copy_to_user(ptr, &v.to_ne_bytes()) { Ok(()) => 0, Err(e) => err(e) }
}

/// Linux `put_user(me->clear_child_tid, (int __user * __user *)arg2)` —
/// the value is a POINTER, so eight bytes on LP64. # C: O(1)
fn put_user_u64(ptr: u64, v: u64) -> i64 {
    match uaccess::copy_to_user(ptr, &v.to_ne_bytes()) { Ok(()) => 0, Err(e) => err(e) }
}

/// `PR_SET_PDEATHSIG` — Linux stores the signal under `tasklist_lock` so the
/// value a concurrently-exiting parent reads in `forget_original_parent` is
/// never torn. `reparent_children` reads it with the same atomic.
/// # C: O(1)
pub fn set_pdeathsig(cur: &Task, sig: u32) -> i64 {
    cur.pdeathsig.store(sig, Ordering::Release);
    0
}

/// `PR_GET_PDEATHSIG`. # C: O(1)
pub fn get_pdeathsig(cur: &Task, ptr: u64) -> i64 {
    put_user_i32(ptr, cur.pdeathsig.load(Ordering::Acquire) as i32)
}

/// `PR_SET_CHILD_SUBREAPER` — Linux `me->signal->is_child_subreaper = !!arg2`.
///
/// Process-wide, not per-thread: it lives on the thread group so any thread
/// may arm it for the whole process, exactly as Linux keeps it on
/// `signal_struct`. `live::zombies::reparent::find_new_reaper` reads it while
/// walking the dying task's ancestor chain, which is what makes the flag do
/// something rather than merely round-trip.
/// # C: O(1)
pub fn set_child_subreaper(cur: &Task, on: bool) -> i64 {
    cur.thread_group.set_child_subreaper(on);
    0
}

/// `PR_GET_CHILD_SUBREAPER`. # C: O(1)
pub fn get_child_subreaper(cur: &Task, ptr: u64) -> i64 {
    put_user_i32(ptr, cur.thread_group.is_child_subreaper() as i32)
}

/// `PR_SET_NO_NEW_PRIVS` — Linux `task_set_no_new_privs(current)`. One-way:
/// there is no clear path in Linux and none here. Inherited by fork
/// (`live::spawn`) and enforced at execve (`syscalls::execve_common`), which
/// is what makes the bit mean something rather than merely round-trip.
/// # C: O(1)
pub fn set_no_new_privs(cur: &Task) -> i64 {
    cur.no_new_privs.store(true, Ordering::Release);
    0
}

/// `PR_GET_NO_NEW_PRIVS` — returns the flag as the syscall VALUE. # C: O(1)
pub fn get_no_new_privs(cur: &Task) -> i64 {
    cur.no_new_privs.load(Ordering::Acquire) as i64
}

/// `PR_SET_TIMERSLACK` — Linux skips RT and deadline tasks entirely
/// (`if (rt_or_dl_task_policy(current)) break;`, returning 0 without a
/// change), and treats `arg2 == 0` as "restore this task's inherited
/// default", not "zero slack".
/// # C: O(1)
pub fn set_timerslack(cur: &Task, ns: u64) -> i64 {
    if cur.is_rt_or_dl_policy() { return 0; }
    let v = if ns == 0 { cur.default_timer_slack_ns.load(Ordering::Acquire) } else { ns };
    cur.timer_slack_ns.store(v, Ordering::Release);
    0
}

/// `PR_GET_TIMERSLACK` — returns the value, not 0. # C: O(1)
pub fn get_timerslack(cur: &Task) -> i64 {
    cur.timer_slack_ns.load(Ordering::Acquire) as i64
}

/// `PR_SET_THP_DISABLE` — Linux keeps two mutually exclusive `mm` flags;
/// `except_advised` selects the softer one. # C: O(1)
pub fn set_thp_disable(cur: &Task, disable: bool, except_advised: bool) -> i64 {
    let state = if !disable { crate::task::THP_DISABLE_OFF }
        else if except_advised { crate::task::THP_DISABLE_EXCEPT_ADVISED }
        else { crate::task::THP_DISABLE_COMPLETELY };
    cur.thp_disable.store(state, Ordering::Release);
    0
}

/// `PR_GET_THP_DISABLE`. # C: O(1)
pub fn get_thp_disable(cur: &Task) -> i64 {
    decide::thp_disable_report(cur.thp_disable.load(Ordering::Acquire))
}

/// `PR_MCE_KILL(PR_MCE_KILL_CLEAR)` — `current->flags &= ~PF_MCE_PROCESS`.
/// # C: O(1)
pub fn mce_kill_clear(cur: &Task) -> i64 {
    cur.mce_kill.fetch_and(!crate::task::MCE_KILL_PROCESS, Ordering::AcqRel);
    0
}

/// `PR_MCE_KILL(PR_MCE_KILL_SET, policy)`. # C: O(1)
pub fn mce_kill_set(cur: &Task, policy: u64) -> i64 {
    cur.mce_kill.store(decide::mce_kill_apply(policy), Ordering::Release);
    0
}

/// `PR_MCE_KILL_GET`. # C: O(1)
pub fn mce_kill_get(cur: &Task) -> i64 {
    decide::mce_kill_report(cur.mce_kill.load(Ordering::Acquire))
}

/// `PR_GET_TID_ADDRESS` — Linux `prctl_get_tid_address` writes
/// `me->clear_child_tid` (the pointer `set_tid_address(2)` / `CLONE_CHILD_CLEARTID`
/// installed) through the user pointer.
/// # C: O(1)
pub fn get_tid_address(cur: &Task, ptr: u64) -> i64 {
    put_user_u64(ptr, cur.clear_child_tid.load(Ordering::Acquire))
}

/// `PR_GET_TSC` — Linux `get_tsc_mode(adr)` PUTS an `unsigned int` through
/// `adr` and returns 0 (or EFAULT); the mode is not the syscall value. This
/// port never arms `TIF_NOTSC`, so the reported mode is always
/// `PR_TSC_ENABLE`, which is the truth about the CPU state userspace sees.
/// # C: O(1)
pub fn get_tsc(ptr: u64) -> i64 { put_user_u32(ptr, PR_TSC_ENABLE) }

/// `PR_SET_TSC` — Linux `set_tsc_mode(val)` toggles `CR4.TSD` per task.
///
/// `PR_TSC_ENABLE` is already the standing state, so accepting it is exact.
/// `PR_TSC_SIGSEGV` needs a per-task `CR4.TSD` toggle carried through the
/// context-switch path plus a `#GP` classifier that raises SIGSEGV on a
/// trapped `rdtsc` — none of which this port has. Returning 0 for it would
/// tell a sandbox its TSC is trapped when `rdtsc` still runs freely, so it is
/// refused instead.
/// # C: O(1)
pub fn set_tsc(mode: u32) -> i64 {
    if mode == PR_TSC_ENABLE { 0 } else { err(Errno::Einval) }
}
