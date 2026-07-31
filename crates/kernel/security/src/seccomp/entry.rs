// Live-task glue: `__secure_computing` (per-syscall evaluation) and
// `do_seccomp` (install). Every decision this file reaches for lives in
// `action.rs` / `install.rs` / `flags.rs` / `verifier.rs`; what remains here
// is reading the running task's state and mutating it.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use super::action::{self, Verdict};
use super::insn::SeccompData;
use super::install::{self, InstallCtx};
use super::interp;
use super::uapi::*;
use super::user;
use super::verifier;

/// `sizeof(struct seccomp_notif)` = u64 id + u32 pid + u32 flags +
/// `struct seccomp_data`.
const SECCOMP_NOTIF_BYTES: u16 = 8 + 4 + 4 + SECCOMP_DATA_BYTES as u16;
/// `sizeof(struct seccomp_notif_resp)` = u64 id + s64 val + s32 error + u32 flags.
const SECCOMP_NOTIF_RESP_BYTES: u16 = 8 + 8 + 4 + 4;

/// Linux `seccomp_mode(&current->seccomp)`. The canonical cell, never
/// re-derived from chain emptiness: STRICT installs no filter at all, so an
/// empty chain cannot tell mode 0 from mode 1.
/// # C: O(1)
pub fn mode_of_current() -> u32 {
    match sched::current() {
        Some(c) => c.seccomp_mode.load(Ordering::Acquire) as u32,
        None => SECCOMP_MODE_DISABLED,
    }
}

/// `__secure_computing` — called from the syscall dispatch head with the
/// syscall number AS THE CALLING ABI NUMBERS IT, its six raw arguments, and
/// the trapped user PC.
///
/// Returns the verdict for the shim to execute; `Verdict::Allow` means
/// dispatch normally. The shim, not this crate, owns killing and signalling
/// (`docs/53`): `security` cannot reach `do_exit` without a dependency cycle.
/// # C: O(F x I)
pub fn check(nr: u64, args: &[u64; 6], ip: u64) -> Verdict {
    let cur = match sched::current() { Some(c) => c, None => return Verdict::Allow };
    // `if (IS_ENABLED(CONFIG_CHECKPOINT_RESTORE) && current->ptrace &
    // PT_SUSPEND_SECCOMP) return 0;` — a CAP_SYS_ADMIN tracer has suspended
    // filtering entirely for this tracee (checkpoint/restore).
    let opts = cur.ptrace_options.load(Ordering::Acquire);
    if opts & PTRACE_O_SUSPEND_SECCOMP != 0 { return Verdict::Allow; }

    match cur.seccomp_mode.load(Ordering::Acquire) as u32 {
        SECCOMP_MODE_DISABLED => Verdict::Allow,
        SECCOMP_MODE_STRICT => {
            if action::strict_allows(nr as i32) { Verdict::Allow }
            else { die(&cur) }
        }
        SECCOMP_MODE_FILTER => {
            let d = SeccompData { nr: nr as i32, arch: native_audit_arch(), ip, args: *args };
            let ret = {
                let chain = cur.seccomp_filters.lock();
                // `WARN_ON(f == NULL) return SECCOMP_RET_KILL_PROCESS` —
                // "Ensure unexpected behavior doesn't result in failing open".
                if chain.is_empty() { drop(chain); return kill_process(&cur, nr, ip); }
                interp::run_chain(&chain, &d)
            };
            let tracer_armed = cur.traced_by.load(Ordering::Acquire) != 0
                && opts & PTRACE_O_TRACESECCOMP != 0;
            let v = action::decide(ret, &d, tracer_armed);
            // `current->seccomp.mode = SECCOMP_MODE_DEAD` runs BEFORE the
            // kill, so a task that somehow survives is caught by the
            // MODE_DEAD arm on its next syscall instead of being filtered
            // again.
            if matches!(v, Verdict::KillThread(_) | Verdict::KillProcess(_)) {
                cur.seccomp_mode.store(SECCOMP_MODE_DEAD as u8, Ordering::Release);
            }
            v
        }
        // `case SECCOMP_MODE_DEAD: WARN_ON_ONCE(1); do_exit(SIGKILL);`
        _ => Verdict::DieSigkill,
    }
}

fn die(_cur: &sched::Task) -> Verdict {
    _cur.seccomp_mode.store(SECCOMP_MODE_DEAD as u8, Ordering::Release);
    Verdict::DieSigkill
}

fn kill_process(cur: &sched::Task, nr: u64, ip: u64) -> Verdict {
    cur.seccomp_mode.store(SECCOMP_MODE_DEAD as u8, Ordering::Release);
    Verdict::KillProcess(action::Sigsys {
        call_addr: ip, syscall: nr as i32, arch: native_audit_arch(), errno: 0,
    })
}

/// `seccomp(2)` — slot 317, and the shared back end of
/// `prctl(PR_SET_SECCOMP)`.
/// # C: O(filter_len)
pub fn sys_seccomp(args: &syscall::SyscallArgs) -> i64 {
    do_seccomp(args.a0, args.a1, args.a2)
}

/// Linux `do_seccomp` — the common entry point for both `seccomp(2)` and
/// `prctl(PR_SET_SECCOMP)`.
/// # C: O(filter_len)
pub fn do_seccomp(op: u64, flags: u64, uargs: u64) -> i64 {
    match do_seccomp_inner(op, flags, uargs) {
        Ok(v) => v,
        Err(e) => -(e.as_i32() as i64),
    }
}

fn do_seccomp_inner(op: u64, flags: u64, uargs: u64) -> Result<i64, Errno> {
    let cur = sched::current().ok_or(Errno::Esrch)?;
    super::flags::validate_op_flags(op, flags, uargs)?;
    match op {
        SECCOMP_SET_MODE_STRICT => {
            if !install::may_assign_mode(cur.seccomp_mode.load(Ordering::Acquire) as u32,
                                         SECCOMP_MODE_STRICT) { return Err(Errno::Einval); }
            cur.seccomp_mode.store(SECCOMP_MODE_STRICT as u8, Ordering::Release);
            Ok(0)
        }
        SECCOMP_SET_MODE_FILTER => set_mode_filter(&cur, flags, uargs),
        SECCOMP_GET_ACTION_AVAIL => install::action_avail(user::read_u32(uargs)?).map(|_| 0),
        SECCOMP_GET_NOTIF_SIZES => {
            user::write_notif_sizes(uargs,
                [SECCOMP_NOTIF_BYTES, SECCOMP_NOTIF_RESP_BYTES, SECCOMP_DATA_BYTES as u16])?;
            Ok(0)
        }
        _ => Err(Errno::Einval),
    }
}

/// `seccomp_set_mode_filter`. The step order is Linux's and is load-bearing;
/// see `install::pre_verify_gate`.
fn set_mode_filter(cur: &sched::Task, flags: u64, uargs: u64) -> Result<i64, Errno> {
    // `seccomp_prepare_user_filter`: the fprog header copy is the first thing
    // after the flag rules, so a bad pointer is EFAULT even when `len` would
    // have been EINVAL.
    let (len, filter_p) = user::read_fprog(uargs)?;
    let ctx = InstallCtx {
        flags,
        len: len as usize,
        no_new_privs: cur.no_new_privs.load(Ordering::Acquire),
        // `ns_capable_noaudit` — the NOAUDIT form. `Task::has_cap` latches
        // `PF_SUPERPRIV`, which this check must not do.
        cap_sys_admin: cur.creds.has_cap(sched::cap::SYS_ADMIN),
        cur_mode: cur.seccomp_mode.load(Ordering::Acquire) as u32,
    };
    install::pre_verify_gate(&ctx)?;
    if let Some(e) = install::listener_unsupported(flags) { return Err(e); }
    let prog = user::read_prog(filter_p, ctx.len)?;
    verifier::check_seccomp_filter(&prog)?;
    install::post_verify_gate(&ctx)?;
    attach(cur, prog, flags)
}

/// `seccomp_attach_filter` + `seccomp_assign_mode`.
///
/// Order is Linux's and is load-bearing: the total-length cap and, for
/// `SECCOMP_FILTER_FLAG_TSYNC`, the whole-group eligibility scan run BEFORE
/// the filter is attached to the caller, so a refused TSYNC leaves the caller
/// exactly as it was.
///
/// A refused TSYNC returns the offending thread's POSITIVE vpid, not an
/// errno — the caller cannot otherwise tell which thread blocked it — unless
/// `SECCOMP_FILTER_FLAG_TSYNC_ESRCH` asked for a plain `-ESRCH`.
fn attach(cur: &sched::Task, prog: Vec<u64>, flags: u64) -> Result<i64, Errno> {
    use super::flags::{SECCOMP_FILTER_FLAG_TSYNC, SECCOMP_FILTER_FLAG_TSYNC_ESRCH};
    if install::total_insns_exceeded(chain_insns(cur), prog.len()) { return Err(Errno::Enomem); }
    if flags & SECCOMP_FILTER_FLAG_TSYNC != 0 {
        if let Some(vpid) = can_sync_threads(cur) {
            if flags & SECCOMP_FILTER_FLAG_TSYNC_ESRCH != 0 { return Err(Errno::Esrch); }
            return Ok(vpid as i64);
        }
    }
    cur.seccomp_filters.lock().push(sched::seccomp_filter::SeccompFilter::new(prog, flags));
    cur.seccomp_mode.store(SECCOMP_MODE_FILTER as u8, Ordering::Release);
    if flags & SECCOMP_FILTER_FLAG_TSYNC != 0 { sync_threads(cur); }
    Ok(0)
}

/// Total cBPF instructions already on this task's chain, with Linux's
/// `walker->prog->len + 4` per-filter penalty.
fn chain_insns(cur: &sched::Task) -> usize {
    cur.seccomp_filters.lock().iter().map(|f| f.len() + install::FILTER_PENALTY_INSNS).sum()
}

/// `seccomp_can_sync_threads` — the eligibility scan, run against the
/// caller's chain BEFORE the new filter joins it. Returns the vpid of the
/// first thread that cannot be synchronised, or `None` when all can.
fn can_sync_threads(cur: &sched::Task) -> Option<u32> {
    let mine: Vec<sched::seccomp_filter::SeccompFilter> = cur.seccomp_filters.lock().clone();
    for (vtid, tid) in sched::registry::thread_entries(cur.tgid.load(Ordering::Acquire)) {
        if tid == cur.tid { continue; }
        let Some(t) = sched::registry::lookup(tid) else { continue };
        // Unconfined threads are always eligible; a confined one must already
        // be running an ANCESTOR of the caller's chain — Linux
        // `is_ancestor(thread->seccomp.filter, caller->seccomp.filter)`,
        // which with per-task chain copies is "a prefix of the caller's".
        if t.seccomp_mode.load(Ordering::Acquire) as u32 == SECCOMP_MODE_DISABLED { continue; }
        let theirs = t.seccomp_filters.lock();
        if theirs.len() <= mine.len() && theirs[..] == mine[..theirs.len()] { continue; }
        return Some(if vtid != 0 { vtid } else { tid });
    }
    None
}

/// `seccomp_sync_threads` — every OTHER thread in the group gets the caller's
/// whole chain, the caller's `no_new_privs`, and `SECCOMP_MODE_FILTER` if it
/// was previously unconfined. Eligibility was settled by `can_sync_threads`.
fn sync_threads(cur: &sched::Task) {
    let mine: Vec<sched::seccomp_filter::SeccompFilter> = cur.seccomp_filters.lock().clone();
    let nnp = cur.no_new_privs.load(Ordering::Acquire);
    let tgid = cur.tgid.load(Ordering::Acquire);
    for (_vtid, tid) in sched::registry::thread_entries(tgid) {
        if tid == cur.tid { continue; }
        let Some(t) = sched::registry::lookup(tid) else { continue };
        *t.seccomp_filters.lock() = mine.clone();
        // "Don't let an unprivileged task work around the no_new_privs
        // restriction by creating a thread that sets it up, enters seccomp,
        // then dies."
        if nnp { t.no_new_privs.store(true, Ordering::Release); }
        if t.seccomp_mode.load(Ordering::Acquire) as u32 == SECCOMP_MODE_DISABLED {
            t.seccomp_mode.store(SECCOMP_MODE_FILTER as u8, Ordering::Release);
        }
    }
}

/// Linux `prctl_set_seccomp` (`kernel/seccomp.c`): the legacy `prctl` front
/// door onto `do_seccomp`. `SECCOMP_MODE_STRICT` maps onto
/// `SECCOMP_SET_MODE_STRICT` with a forced-NULL filter argument,
/// `SECCOMP_MODE_FILTER` onto `SECCOMP_SET_MODE_FILTER` with arg3 as the
/// `sock_fprog`, anything else EINVAL. Flags are always zero — the `prctl`
/// interface has no flags word.
///
/// Lives here rather than in `sched::prctl` because seccomp is owned by this
/// crate and `security` depends on `sched`, not the other way round.
/// # C: O(filter_len)
pub fn prctl_set_seccomp(mode: u64, filter: u64) -> i64 {
    let Some(op) = prctl_seccomp_op(mode) else { return -(Errno::Einval.as_i32() as i64) };
    let uargs = if op == SECCOMP_SET_MODE_FILTER { filter } else { 0 };
    do_seccomp(op, 0, uargs)
}

/// `prctl_set_seccomp`'s mode -> `do_seccomp` operation mapping.
/// # C: O(1)
pub fn prctl_seccomp_op(mode: u64) -> Option<u64> {
    match mode as u32 {
        SECCOMP_MODE_STRICT => Some(SECCOMP_SET_MODE_STRICT),
        SECCOMP_MODE_FILTER => Some(SECCOMP_SET_MODE_FILTER),
        _ => None,
    }
}
