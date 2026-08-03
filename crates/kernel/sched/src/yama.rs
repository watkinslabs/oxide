// Yama's ptrace restrictions — `security/yama/yama_lsm.c`, reachable through
// `/proc/sys/kernel/yama/ptrace_scope`.
//
// Owned by `sched` beside `ptrace_access` because it is the second half of one
// decision: `__ptrace_may_access` runs the credential ladder, then the LSM hook
// `security_ptrace_access_check` runs this. A copy anywhere else would let the
// sysctl report a scope the attach path does not apply.
//
// The scope cell is the live one this file consults; procfs binds its leaf to
// `scope()` / `set_scope()` rather than keeping a value of its own.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};

use crate::Task;

/// `YAMA_SCOPE_*`.
pub const SCOPE_DISABLED:   u8 = 0;
pub const SCOPE_RELATIONAL: u8 = 1;
pub const SCOPE_CAPABILITY: u8 = 2;
pub const SCOPE_NO_ATTACH:  u8 = 3;
/// Highest value `/proc/sys/kernel/yama/ptrace_scope` accepts.
pub const SCOPE_MAX: u8 = SCOPE_NO_ATTACH;

/// `ptrace_scope` — Yama's default when the LSM is built in.
static SCOPE: AtomicU8 = AtomicU8::new(SCOPE_RELATIONAL);

/// # C: O(1)
pub fn scope() -> u8 { SCOPE.load(Ordering::Acquire) }

/// Install a new scope.
///
/// The knob locks only once it reaches its MAXIMUM, not on every raise. The
/// reference's handler copies the table and, when the current value already
/// equals the maximum, raises the minimum to that maximum — so `[0, max)` stays
/// freely writable in both directions and only `max` is a one-way door:
///
///   /* Lock the max value if it ever gets set. */
///   if (*(int *)table_copy.data == *(int *)table_copy.extra2)
///           table_copy.extra1 = table_copy.extra2;
///
/// Refusing every lowering instead made the default value a floor, so the
/// boot-time sysctl apply — which writes 0 from the shipped configuration —
/// was refused with EINVAL and failed the whole unit.
///
/// Returns false for a refused write (the reference's `-EINVAL`).
/// # C: O(1)
pub fn set_scope(new: i64) -> bool {
    if !(0..=SCOPE_MAX as i64).contains(&new) { return false; }
    let new = new as u8;
    // Locked at the top: from the maximum, the only value still in range is
    // the maximum itself.
    if SCOPE.load(Ordering::Acquire) == SCOPE_MAX && new != SCOPE_MAX { return false; }
    SCOPE.store(new, Ordering::Release);
    true
}

/// One `PR_SET_PTRACER` relation: `tracee` (a thread-group leader tid) allows
/// `tracer` — or, when `tracer` is `None`, any descendant of any process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Relation { tracee: u32, tracer: Option<u32> }

static RELATIONS: Spinlock<Vec<Relation>, TaskListClass> = Spinlock::new(Vec::new());

/// `yama_ptracer_add`: record that `tracee` permits `tracer`. `tracer ==
/// None` is `PR_SET_PTRACER_ANY`. A second call for the same tracee REPLACES
/// the first, matching Linux's `if (relation->tracee == tracee) { ... break; }`
/// update-in-place.
/// # C: O(N_relations)
pub fn ptracer_add(tracee: u32, tracer: Option<u32>) {
    let mut g = RELATIONS.lock();
    if let Some(r) = g.iter_mut().find(|r| r.tracee == tracee) { r.tracer = tracer; return; }
    g.push(Relation { tracee, tracer });
}

/// `yama_ptracer_del(NULL, myself)` — `prctl(PR_SET_PTRACER, 0)`.
/// # C: O(N_relations)
pub fn ptracer_del(tracee: u32) { RELATIONS.lock().retain(|r| r.tracee != tracee); }

/// Drop every relation naming a dead task, in either role. Linux does this
/// from `yama_task_free` / the `invalid` flag; without it a recycled tid
/// inherits a dead process's exemption.
/// # C: O(N_relations)
pub fn task_free(tid: u32) {
    RELATIONS.lock().retain(|r| r.tracee != tid && r.tracer != Some(tid));
}

/// The recorded exemption for `tracee`, if any: `Some(None)` is
/// `PR_SET_PTRACER_ANY`, `Some(Some(tid))` names one permitted ancestor.
/// # C: O(N_relations)
fn relation_for(tracee: u32) -> Option<Option<u32>> {
    RELATIONS.lock().iter().find(|r| r.tracee == tracee).map(|r| r.tracer)
}

/// `task_is_descendant(parent, child)` — walk `child`'s real-parent chain,
/// comparing thread-group leaders, looking for `parent`. `tid == 0` (no
/// parent recorded) ends the walk, as Linux's `walker->pid > 0` does.
/// # C: O(depth)
pub fn task_is_descendant(parent_tgid: u32, child: &Task) -> bool {
    if parent_tgid == 0 { return false; }
    let mut walker = child.tgid.load(Ordering::Acquire);
    let mut hops = 0usize;
    while walker != 0 && hops < MAX_ANCESTRY {
        if walker == parent_tgid { return true; }
        let Some(t) = crate::registry::lookup(walker) else { return false };
        let parent = t.parent_tid.load(Ordering::Acquire);
        if parent == 0 { return false; }
        walker = match crate::registry::lookup(parent) {
            Some(p) => p.tgid.load(Ordering::Acquire),
            None => return false,
        };
        hops += 1;
    }
    false
}

/// Ceiling on the ancestry walk. A parent chain is acyclic by construction
/// (reparenting only ever points at an ancestor or the namespace init), so
/// this only bounds the cost of a pathological process tree.
const MAX_ANCESTRY: usize = 4096;

/// `ptracer_exception_found`: an ALREADY-ESTABLISHED tracing relationship is
/// itself an exception — that is what lets `process_vm_readv` follow an
/// attach — and otherwise a `PR_SET_PTRACER` relation whose named tracer is
/// `tracer` itself or an ancestor of it.
/// # C: O(N_relations + depth)
pub fn exception_found(tracer: &Task, tracee: &Task) -> bool {
    let established = tracee.traced_by.load(Ordering::Acquire);
    if established != 0 {
        if let Some(t) = crate::registry::lookup(established) {
            if t.tgid.load(Ordering::Acquire) == tracer.tgid.load(Ordering::Acquire) {
                return true;
            }
        }
    }
    // The relation is recorded against the thread-group leader.
    match relation_for(tracee.tgid.load(Ordering::Acquire)) {
        None => false,
        Some(None) => true,
        Some(Some(allowed)) => task_is_descendant(allowed, tracer),
    }
}

/// `yama_ptrace_access_check(child, PTRACE_MODE_ATTACH*)`. Runs only for an
/// ATTACH-class access; the read-only `/proc` modes are not restricted by
/// Yama. `Err(())` is Linux's `-EPERM`.
///
/// The three restrictive scopes, in Linux's order:
///   * RELATIONAL — the tracee must be a descendant of the tracer, or carry a
///     matching `PR_SET_PTRACER` exemption, or the tracer must hold
///     CAP_SYS_PTRACE over the tracee's user namespace.
///   * CAPABILITY — CAP_SYS_PTRACE, nothing else.
///   * NO_ATTACH — refused unconditionally, capability or not.
/// # C: O(N_relations + depth)
pub fn ptrace_access_check(tracer: &Task, tracee: &Task) -> Result<(), ()> {
    match scope() {
        SCOPE_DISABLED => Ok(()),
        SCOPE_RELATIONAL => {
            if task_is_descendant(tracer.tgid.load(Ordering::Acquire), tracee) { return Ok(()); }
            if exception_found(tracer, tracee) { return Ok(()); }
            if tracer.has_cap(crate::task::cap::SYS_PTRACE) { return Ok(()); }
            Err(())
        }
        SCOPE_CAPABILITY => {
            if tracer.has_cap(crate::task::cap::SYS_PTRACE) { Ok(()) } else { Err(()) }
        }
        _ => Err(()),
    }
}

/// `yama_ptrace_traceme(parent)` — the `PTRACE_TRACEME` direction, which the
/// two LOWER scopes do not restrict at all: a process volunteering to be
/// traced by its own parent is not the attack Yama exists to stop.
/// # C: O(1)
pub fn ptrace_traceme(parent: &Task) -> Result<(), ()> {
    match scope() {
        SCOPE_CAPABILITY => {
            if parent.has_cap(crate::task::cap::SYS_PTRACE) { Ok(()) } else { Err(()) }
        }
        SCOPE_NO_ATTACH => Err(()),
        _ => Ok(()),
    }
}

#[cfg(test)]
#[path = "yama/tests.rs"] mod tests;
