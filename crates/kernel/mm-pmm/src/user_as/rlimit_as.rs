// The live-state half of the address-space rlimits: read the faulting /
// mapping task's `RLIMIT_AS` and `RLIMIT_STACK`, read the mm's current mapped
// size, and hand the VMA machinery the two byte caps it applies.
//
// The DECISION (sentinel handling, page truncation, which limit bounds what)
// belongs to `sched::rlimit::vm` and is unit-tested there; this file only
// gathers, per `docs/53`.

use syscall::errno::Errno;
use vmm::AddressSpace;

/// This task's `(soft, _)` pair for one resource, or `RLIM_INFINITY` when
/// there is no current task (boot anchor, kernel threads).
/// # C: O(1)
fn soft_limit(resource: usize) -> u64 {
    match sched::live::current() {
        Some(cur) => cur.rlimit(resource).0,
        None => sched::rlimit::INFINITY,
    }
}

/// `(max_size, max_grow)` for [`AddressSpace::try_grow_stack`] — Linux
/// `acct_stack_growth`'s `RLIMIT_STACK` and `may_expand_vm` tests, evaluated
/// against this mm and the faulting task.
/// # C: O(N_vmas)
pub fn stack_growth_caps(as_: &AddressSpace) -> (u64, u64) {
    use sched::rlimit::rlim;
    let max_size = sched::rlimit::vm::stack_size_cap(soft_limit(rlim::STACK));
    let rlimit_as = soft_limit(rlim::AS);
    // Only pay for the O(N) walk when a finite limit can actually bind.
    let max_grow = if rlimit_as == sched::rlimit::INFINITY { u64::MAX } else {
        sched::rlimit::vm::as_headroom_bytes(as_.total_mapped_bytes(), rlimit_as)
    };
    (max_size, max_grow)
}

/// Linux `may_expand_vm`'s address-space test for a new mapping of
/// `grow_bytes`, run before the VMA is placed. `Err(ENOMEM)` is what every
/// `may_expand_vm` refusal turns into at the syscall boundary.
/// # C: O(N_vmas) when a finite limit is set, O(1) otherwise
pub fn admit_as_growth(as_: &AddressSpace, grow_bytes: u64) -> Result<(), i64> {
    let rlimit_as = soft_limit(sched::rlimit::rlim::AS);
    if rlimit_as == sched::rlimit::INFINITY { return Ok(()); }
    if sched::rlimit::vm::may_expand_as(as_.total_mapped_bytes(), grow_bytes, rlimit_as) {
        return Ok(());
    }
    Err(-(Errno::Enomem.as_i32() as i64))
}

/// [`admit_as_growth`] against the address space the running task maps.
/// A context with no current task (boot anchor) has no limit to enforce.
/// # C: O(N_vmas) when a finite limit is set, O(1) otherwise
pub fn admit_current_as_growth(grow_bytes: u64) -> Result<(), i64> {
    if soft_limit(sched::rlimit::rlim::AS) == sched::rlimit::INFINITY { return Ok(()); }
    let Some(cur) = sched::live::current() else { return Ok(()) };
    // SAFETY: syscall / fault context — the running task on this CPU is the sole writer of its mm slot.
    let Some(mm) = (unsafe { cur.mm_ref() }) else { return Ok(()) };
    admit_as_growth(mm, grow_bytes)
}
