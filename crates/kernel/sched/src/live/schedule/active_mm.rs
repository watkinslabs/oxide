use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, Ordering};

use vmm::AddressSpace;
use crate::live::runqueue::Runqueue;

/// This CPU's logical index (clamped to `MAX_CPUS`), matching the TLB
/// shootdown sender's `this_cpu()` so the `mm_cpumask` bit set/cleared in
/// the switch path is the bit the sender targets. Host builds are UP -> 0.
/// # C: O(1)
#[inline]
pub(crate) fn sched_current_cpu() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Per-CPU lazy-TLB `active_mm` slot (Linux `mmgrab`/`mmdrop` reference;
/// `13§8`, GAP-2 use-after-free fix). When this CPU switches FROM a user task
/// TO a kthread/idle (`next.mm == None`) it goes lazy-TLB: it keeps the
/// outgoing task's page-table root in CR3 WITHOUT issuing a fresh `activate`,
/// and keeps its `mm_cpumask` bit set - but it does NOT hold that task's `mm`
/// Arc. The task can then exit, be reaped, and drop the last `Arc<AddressSpace>`
/// on another CPU, so `as_teardown` frees the root frame out from under this
/// CPU's live CR3 (PMM reuse then clobbers e.g. the LAPIC PML4 entry -> the
/// intermittent `#PF` on EOI). This slot holds an EXTRA `Arc<AddressSpace>`
/// (Linux `mmgrab`) for the root we are lazily resident on, so its refcount
/// cannot reach zero - hence `as_teardown` cannot run - while a CPU holds it in
/// CR3. The grab is released (Linux `mmdrop`) when the CPU activates a real
/// user root. Indexed by logical CPU; null = this CPU holds no lazy grab.
const NULL_AS: AtomicPtr<AddressSpace> = AtomicPtr::new(core::ptr::null_mut());
static ACTIVE_MM: [AtomicPtr<AddressSpace>; cpu::MAX_CPUS] = [NULL_AS; cpu::MAX_CPUS];

#[cfg(feature = "debug-as-lifetime")]
fn log_transition(event: &'static [u8], cpu: usize, mm: &AddressSpace, prior: Option<&AddressSpace>) {
    let tid = crate::live::current().map(|task| task.tid).unwrap_or(0);
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    let hardware_root = hal_x86_64::read_cr3() & !(hal::PAGE_SIZE_BYTES - 1);
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    let hardware_root = hal_aarch64::read_ttbr0_el1() & !(hal::PAGE_SIZE_BYTES - 1);
    #[cfg(not(target_os = "oxide-kernel"))]
    let hardware_root = 0;
    klog::write_raw(b"[AS-LIFE-SCHED] event=");
    klog::write_raw(event);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(tid as u64);
    klog::write_raw(b" cpu=");
    klog::write_dec_u64(cpu as u64);
    klog::write_raw(b" hw-root=");
    klog::write_hex_u64(hardware_root);
    klog::write_raw(b" mm-root=");
    klog::write_hex_u64(mm.root_pa());
    klog::write_raw(b" prior-root=");
    klog::write_hex_u64(prior.map(AddressSpace::root_pa).unwrap_or(0));
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-as-lifetime"))]
#[inline]
fn log_transition(_event: &'static [u8], _cpu: usize, _mm: &AddressSpace, _prior: Option<&AddressSpace>) {}

/// Linux `mmgrab` (lazy-TLB): pin `mm` as this CPU's `active_mm` so its root
/// frame survives while the CPU stays resident on it in CR3 with no owning
/// task. Stores one extra `Arc` strong ref; any previously-held grab (which
/// should be null when entering lazy from a user task) is reclaimed + dropped
/// defensively so the slot never leaks. # C: O(1)
pub(super) fn active_mm_grab(cpu: usize, mm: &Arc<AddressSpace>, rq: &Runqueue) {
    if cpu >= cpu::MAX_CPUS { return; }
    let raw = Arc::into_raw(Arc::clone(mm)) as *mut AddressSpace;
    let prev = ACTIVE_MM[cpu].swap(raw, Ordering::AcqRel);
    if !prev.is_null() {
        // An unexpected stale grab still cannot be destroyed under rq.inner:
        // transfer it to the same post-switch slot used by the normal drop.
        // SAFETY: `prev` is a live raw Arc held by ACTIVE_MM until this swap;
        // borrowing it for diagnostics does not consume that reference.
        let previous = unsafe { &*prev };
        log_transition(b"active-mm-grab", cpu, mm, Some(previous));
        previous.debug_lifetime_event(b"active-mm-replace");
        let old = rq.prev_mm.swap(prev, Ordering::AcqRel);
        hal::kassert!(old.is_null(), "active_mm overwrote pending rq prev_mm");
    }
}

/// Transfer this CPU's lazy-TLB grab to `rq->prev_mm` for release by the
/// incoming task after it unlocks the runqueue. Address-space destruction can
/// drop file-backed VMAs, perform synchronous writeback and sleep; doing that
/// from the pre-switch rq critical section self-deadlocks on the next
/// `schedule()`. Does not touch `mm_cpumask`: the released mm can be the same
/// mm being switched into, whose bit was just restored. # C: O(1)
pub(super) fn active_mm_defer_drop(cpu: usize, rq: &Runqueue) {
    if cpu >= cpu::MAX_CPUS { return; }
    let prev = ACTIVE_MM[cpu].swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !prev.is_null() {
        let old = rq.prev_mm.swap(prev, Ordering::AcqRel);
        hal::kassert!(old.is_null(), "active_mm overwrote pending rq prev_mm");
    }
}

/// Release the lazy-TLB reference deferred by `active_mm_defer_drop`.
/// Called only after the incoming task has released the rq lock, so the final
/// address-space destructor may block without recursively taking that lock.
/// # C: O(1) excluding address-space destruction
pub(super) fn active_mm_finish_drop(rq: &Runqueue) {
    let prev = rq.prev_mm.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !prev.is_null() {
        // SAFETY: `prev` was transferred from ACTIVE_MM by
        // active_mm_defer_drop and this swap consumes its one raw Arc exactly.
        let previous = unsafe { Arc::from_raw(prev) };
        drop(previous);
    }
}

/// Park a displaced `Arc<AddressSpace>` in this CPU's `active_mm` slot
/// (Linux `exit_mm`: `tsk->mm = NULL` keeps `active_mm` + `mm_count`; the
/// final `mmdrop` runs in `finish_task_switch` AFTER the next root is live).
/// Called by `Task::replace_mm` for the Arc it displaces: on `sys_exit` /
/// signal-death the dying task clears its `mm` BEFORE the final `schedule()`,
/// so dropping the last Arc there would run `as_teardown` - freeing the root
/// frame for PMM reuse - while this CPU still has it in CR3/TTBR0 (every
/// kernel page-walk then traverses a clobbered root: the intermittent
/// random-victim exec/ld.so corruption). Parking defers the drop to the next
/// `active_mm_drop`, which fires only after `activate` installs a different
/// root. Slot-occupant swap is safe: while a user task runs, its activation
/// already emptied the slot, so any occupant here is a dead root (see
/// `active_mm_grab`). # C: O(1)
pub fn park_active_mm(mm: Arc<AddressSpace>) {
    let me = sched_current_cpu();
    if me >= cpu::MAX_CPUS { return; }
    // Keep one ordinary Arc only while emitting the transition. The active
    // slot retains the original Arc below; no diagnostic borrows a raw slot.
    let held = Arc::clone(&mm);
    let raw = Arc::into_raw(mm) as *mut AddressSpace;
    let prev = ACTIVE_MM[me].swap(raw, Ordering::AcqRel);
    if !prev.is_null() {
        // SAFETY: `prev` was installed by active_mm_grab/park_active_mm via Arc::into_raw on a live Arc<AddressSpace>; reclaiming drops that one parked strong ref.
        let previous = unsafe { Arc::from_raw(prev) };
        log_transition(b"park-active-mm", me, &held, Some(&previous));
        previous.debug_lifetime_event(b"park-replace");
        drop(previous);
    } else {
        log_transition(b"park-active-mm", me, &held, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SchedClass, Task};

    #[test]
    fn lazy_mm_release_is_deferred_past_the_runqueue_lock() {
        let mm = AddressSpace::new(0).expect("hosted address space");
        let idle = Arc::new(Task::new(9900, "idle", SchedClass::Idle));
        let rq = Runqueue::new(0, idle);
        let raw = Arc::into_raw(Arc::clone(&mm)) as *mut AddressSpace;
        assert!(ACTIVE_MM[0].swap(raw, Ordering::AcqRel).is_null());

        let guard = rq.inner.lock();
        active_mm_defer_drop(0, &rq);
        assert!(ACTIVE_MM[0].load(Ordering::Acquire).is_null());
        assert_eq!(rq.prev_mm.load(Ordering::Acquire), raw);
        assert_eq!(Arc::strong_count(&mm), 2,
            "deferred mm was destroyed inside the rq critical section");

        drop(guard);
        active_mm_finish_drop(&rq);
        assert!(rq.prev_mm.load(Ordering::Acquire).is_null());
        assert_eq!(Arc::strong_count(&mm), 1,
            "post-unlock finish did not consume the deferred mm reference");
    }
}
