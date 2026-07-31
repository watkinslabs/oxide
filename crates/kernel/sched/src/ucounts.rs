// `RLIMIT_NPROC` accounting wired to real tasks — Linux `copy_creds`'
// `inc_rlimit_ucounts`, `copy_process`' EAGAIN gate, `__exit_signal`'s
// release, `set_cred_ucounts` + `flag_nproc_exceeded` in the `set*uid`
// family, and `bprm_execve`'s deferred EAGAIN.
//
// The counted unit is the TASK, threads included, exactly as `RLIMIT_NPROC`
// counts them on Linux. The account a task is charged to is LATCHED on the
// task at charge time rather than recomputed at release time: a task's user
// namespace membership is torn down before it reaches its terminal state, so
// recomputing at exit would release the charge against the wrong account and
// leak the real one forever.
//
// `flag_nproc_exceeded` is why `setuid(2)` cannot fail here. Too much
// software ignores its return value, so Linux defers the failure to the next
// `execve(2)` instead — a set-uid helper that drops into an over-quota
// account still runs, but it cannot go on to exec anything.

use core::sync::atomic::Ordering;

use namespace_identity::NamespaceKind;
use ucounts::{Counter, UcountKey, RLIM_INFINITY};

use crate::rlimit::rlim;
use crate::Task;

/// The account `task` is charged to right now (Linux `task_ucounts`).
/// # C: O(1)
pub fn charged_key(task: &Task) -> UcountKey {
    UcountKey::new(task.ucounts_ns.load(Ordering::Acquire),
        task.ucounts_uid.load(Ordering::Acquire))
}

/// The account `task`'s CURRENT credentials name (Linux `set_cred_ucounts`'
/// `alloc_ucounts(new->user_ns, new->uid)`) — the task's user namespace and
/// its REAL uid, which is the id `RLIMIT_NPROC` is accounted against.
/// # C: O(1); # Lk: Namespace
pub fn current_key(task: &Task) -> UcountKey {
    let ns = task.namespace_owner(NamespaceKind::User).map_or(0, |owner| owner.id().as_u64());
    UcountKey::new(ns, task.creds.ruid.load(Ordering::Acquire))
}

/// This task's effective `RLIMIT_NPROC` soft limit. # C: O(1); # Lk: TaskList
pub fn nproc_limit(task: &Task) -> u64 { task.rlimit(rlim::NPROC).0 }

/// Charge one live task to its current account (Linux `copy_creds`'
/// `inc_rlimit_ucounts(..., UCOUNT_RLIMIT_NPROC, 1)`). Idempotent: a task
/// already charged is left alone, so a double call cannot inflate an account.
/// # C: O(chain); # Lk: TaskList
pub fn charge_task(task: &Task) {
    if task.nproc_charged.swap(true, Ordering::AcqRel) { return; }
    let key = current_key(task);
    task.ucounts_ns.store(key.ns, Ordering::Release);
    task.ucounts_uid.store(key.uid, Ordering::Release);
    ucounts::inc_rlimit(key, Counter::Nproc, 1);
}

/// Release a task's charge (Linux `__exit_signal`'s
/// `dec_rlimit_ucounts`). Idempotent, so a task that reaches its terminal
/// state twice cannot under-count its account into permanent free capacity.
/// # C: O(chain); # Lk: TaskList
pub fn uncharge_task(task: &Task) {
    if !task.nproc_charged.swap(false, Ordering::AcqRel) { return; }
    ucounts::dec_rlimit(charged_key(task), Counter::Nproc, 1);
}

/// Linux `copy_process`' admission gate, run once the child is charged:
///
/// ```text
/// if (is_rlimit_overlimit(task_ucounts(p), UCOUNT_RLIMIT_NPROC, rlimit(RLIMIT_NPROC))) {
///         if (p->real_cred->user != INIT_USER &&
///             !capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN))
///                 goto bad_fork_cleanup_count;
/// }
/// current->flags &= ~PF_NPROC_EXCEEDED;
/// ```
///
/// The initial namespace's root is exempt outright — a root fork bomb must
/// not lock root out of its own recovery shell — as is any task holding
/// `CAP_SYS_RESOURCE` or `CAP_SYS_ADMIN`. A refused fork returns EAGAIN and
/// the caller must release the child's charge.
/// # C: O(chain); # Lk: TaskList
pub fn fork_admits(child: &Task, parent: &Task) -> bool {
    let admitted = !nproc_exceeded_for(child)
        || charged_key(child).is_init_user()
        || parent.has_cap(crate::cap::SYS_RESOURCE)
        || parent.has_cap(crate::cap::SYS_ADMIN);
    // The successful fork proves the caller is under its limit again, so a
    // stale deferred-EAGAIN flag must not survive it.
    if admitted { parent.nproc_exceeded.store(false, Ordering::Release); }
    admitted
}

/// Whether `task`'s account is at or past the limit that applies to it.
/// # C: O(chain); # Lk: TaskList
fn nproc_exceeded_for(task: &Task) -> bool {
    ucounts::is_overlimit(charged_key(task), Counter::Nproc, nproc_limit(task))
}

/// Linux `set_cred_ucounts` + `flag_nproc_exceeded`, run by every `set*uid`
/// transition. Moves the task's charge to the account its new real uid
/// names, then arms the deferred `execve` failure when that account is over
/// its limit. NEVER fails — that is the whole point of the deferral.
/// # C: O(chain); # Lk: TaskList
pub fn recharge_after_setuid(task: &Task) {
    let old = charged_key(task);
    let new = current_key(task);
    if new == old { return; }
    if task.nproc_charged.load(Ordering::Acquire) {
        ucounts::inc_rlimit(new, Counter::Nproc, 1);
        ucounts::dec_rlimit(old, Counter::Nproc, 1);
    }
    task.ucounts_ns.store(new.ns, Ordering::Release);
    task.ucounts_uid.store(new.uid, Ordering::Release);
    let armed = nproc_exceeded_for(task) && !new.is_init_user();
    task.nproc_exceeded.store(armed, Ordering::Release);
}

/// Linux `bprm_execve`'s recheck: an `execve` refuses with EAGAIN only when
/// the flag is armed AND the account is STILL over its limit; otherwise the
/// flag is dropped so later execs are not punished for a transient overrun.
/// # C: O(chain); # Lk: TaskList
pub fn execve_admits(task: &Task) -> bool {
    if task.nproc_exceeded.load(Ordering::Acquire) && nproc_exceeded_for(task) { return false; }
    task.nproc_exceeded.store(false, Ordering::Release);
    true
}

/// Linux `create_user_ns`: link a freshly created user namespace to the
/// account that created it and record the ceiling that account was under.
///
/// `enforced_nproc_rlimit()` in full — the ceiling is unbounded only when the
/// creator is the initial namespace's root, because that account is the one
/// `RLIMIT_NPROC` is never enforced against; every other creator hands its
/// own soft limit down as the ceiling its namespace may not exceed.
/// # C: O(chain); # Lk: TaskList
pub fn register_user_namespace(creator: &Task, ns: u64) {
    let key = current_key(creator);
    let ceiling = if key.is_init_user() { RLIM_INFINITY } else {
        let limit = nproc_limit(creator);
        if limit > RLIM_INFINITY as u64 { RLIM_INFINITY } else { limit as i64 }
    };
    ucounts::register_namespace(ns, key, ceiling);
}

/// Drop a user namespace's account link once the namespace is gone.
/// # C: O(log N); # Lk: TaskList
pub fn forget_user_namespace(ns: u64) { ucounts::forget_namespace(ns); }
