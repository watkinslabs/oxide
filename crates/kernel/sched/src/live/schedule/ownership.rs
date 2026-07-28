// Post-mortem for the `schedule()` ownership assertion. Split out of `switch`
// so the switch engine stays the switch engine (`08§7` file cap).

use core::sync::atomic::Ordering;

use crate::Task;
use crate::live::runqueue::global_for;

/// Name the CPU that still owns `t` when `schedule()`'s `on_cpu` claim fails.
/// The three states are distinguishable and each implicates a different path:
/// `current_is_victim` (it is genuinely RUNNING there — something enqueued a
/// live task), `switched_from_is_victim` (it is mid switch-off, so its
/// `finish_task_switch` clear is still pending), or neither (`on_cpu` leaked).
/// # SAFETY: caller is `schedule()`; reads installed runqueue slots only.
/// # C: O(N_cpus)
#[cold]
pub(super) unsafe fn report_ownership_conflict(t: &Task, me: usize) {
    let victim = t as *const Task;
    klog::write_raw(b"[OWNCONFLICT] tid=");           klog::write_dec_u64(t.tid as u64);
    klog::write_raw(b" state=");                      klog::write_dec_u64(t.state() as u64);
    klog::write_raw(b" on_rq=");                      klog::write_dec_u64(t.on_rq.load(Ordering::Acquire) as u64);
    klog::write_raw(b" on_wake_list=");               klog::write_dec_u64(t.on_wake_list.load(Ordering::Acquire) as u64);
    klog::write_raw(b" task.cpu=");                   klog::write_dec_u64(t.cpu.load(Ordering::Acquire) as u64);
    klog::write_raw(b" picked_on_cpu=");              klog::write_dec_u64(me as u64);
    klog::write_raw(b"\n");
    for c in 0..cpu::MAX_CPUS as u32 {
        // SAFETY: `global_for` is sound for any index; `None` unless that CPU
        // has completed `install_global`.
        let orq = match unsafe { global_for(c) } { Some(r) => r, None => continue };
        let cur = orq.current.load(Ordering::Acquire) as *const Task;
        let sf  = orq.switched_from.load(Ordering::Acquire) as *const Task;
        klog::write_raw(b"[OWNCONFLICT] cpu=");       klog::write_dec_u64(c as u64);
        klog::write_raw(b" current_tid=");
        // SAFETY: `current` is non-null after `install_global` and its Arc is held by the slot.
        klog::write_dec_u64(if cur.is_null() { 0 } else { unsafe { (*cur).tid } } as u64);
        klog::write_raw(b" current_is_victim=");      klog::write_dec_u64((cur == victim) as u64);
        klog::write_raw(b" switched_from_is_victim="); klog::write_dec_u64((sf == victim) as u64);
        klog::write_raw(b" nr_running=");             klog::write_dec_u64(orq.nr_running.load(Ordering::Acquire) as u64);
        klog::write_raw(b"\n");
    }
}
